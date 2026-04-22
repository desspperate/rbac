from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager

from asyncpg import CheckViolationError, ForeignKeyViolationError, NotNullViolationError, UniqueViolationError
from loguru import logger
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.constants import RBACConstants
from rbac.enums import PolicyEffectEnum
from rbac.errors import (
    PermissionNotFoundError,
    PermissionsNotFoundError,
    RoleDescriptionInvalidError,
    RoleNameAlreadyExistError,
    RoleNameInvalidError,
    RoleNameNullError,
    RoleNotFoundError,
    UnhandledIntegrityError,
)
from rbac.models import Role, RolePermission
from rbac.repositories import RoleRepository
from rbac.utils import FK_DETAIL_PATTERN, UNSET, Unset, get_asyncpg_error


@asynccontextmanager
async def handle_role_integrity(name: str | None, description: str | None) -> AsyncIterator[None]:
    try:
        yield
    except IntegrityError as e:
        asyncpg_error = get_asyncpg_error(e)
        if asyncpg_error is None:
            raise UnhandledIntegrityError from e

        if isinstance(asyncpg_error, UniqueViolationError | CheckViolationError):
            constraint = getattr(asyncpg_error, "constraint_name", None)
            if not isinstance(constraint, str):
                raise UnhandledIntegrityError from e

            if constraint == Role.UQ_ROLE_NAME and isinstance(name, str):
                raise RoleNameAlreadyExistError(name=name) from e
            if constraint == Role.CK_ROLE_NAME_PATTERN and isinstance(name, str):
                raise RoleNameInvalidError(name=name, pattern=RBACConstants.ROLE_NAME_PATTERN) from e
            if constraint == Role.CK_ROLE_DESCRIPTION_PATTERN and isinstance(description, str):
                raise RoleDescriptionInvalidError(
                    description=description,
                    pattern=RBACConstants.DESCRIPTION_PATTERN,
                ) from e
        elif isinstance(asyncpg_error, NotNullViolationError):
            column = getattr(asyncpg_error, "column", None)
            if not isinstance(column, str):
                raise UnhandledIntegrityError from e

            if column == "name":
                raise RoleNameNullError from e

        raise UnhandledIntegrityError from e


@asynccontextmanager
async def handle_role_permission_integrity() -> AsyncIterator[None]:
    try:
        yield
    except IntegrityError as e:
        asyncpg_error = get_asyncpg_error(e)
        if asyncpg_error is None:
            raise UnhandledIntegrityError from e

        constraint = getattr(asyncpg_error, "constraint_name", None)
        if not isinstance(constraint, str):
            raise UnhandledIntegrityError from e

        if isinstance(asyncpg_error, ForeignKeyViolationError):
            detail = getattr(asyncpg_error, "detail", "")
            failed_value = None
            match = FK_DETAIL_PATTERN.search(detail)
            if match:
                try:
                    failed_value = int(match.group(2))
                except ValueError:
                    raise UnhandledIntegrityError from e
            if not isinstance(failed_value, int):
                raise UnhandledIntegrityError from e

            if constraint == RolePermission.FK_ROLE_PERMISSION_ROLE_ID:
                raise RoleNotFoundError(role_id=failed_value) from e
            elif constraint == RolePermission.FK_ROLE_PERMISSION_PERMISSION_ID:
                raise PermissionNotFoundError(permission_id=failed_value) from e

        raise UnhandledIntegrityError from e


class RoleService:
    def __init__(self, session: AsyncSession, role_repository: RoleRepository) -> None:
        self.session = session
        self.role_repository = role_repository

    async def get_roles(self, page: int, size: int) -> Sequence[Role]:
        logger.info(f"Getting roles for page: {page}, size: {size}")
        return await self.role_repository.list_all(skip=(page - 1) * size, limit=size)

    async def get_role(self, role_id: int) -> Role:
        logger.info(f"Getting role: {role_id}")
        if (role := await self.role_repository.get_by_id(role_id)) is None:
            raise RoleNotFoundError(role_id)
        return role

    async def create_role(self, name: str, description: str | None) -> Role:
        logger.info(f"Creating role: '{name}'")
        async with handle_role_integrity(name=name, description=description):
            role = await self.role_repository.create_role(
                name=name,
                description=description,
            )
        await self.session.commit()
        logger.info(f"Role created: '{name}'")
        return role

    async def delete_role(self, role_id: int) -> None:
        logger.info(f"Deleting role: {role_id}")
        deleted = await self.role_repository.delete_by_id(role_id)
        if not deleted:
            raise RoleNotFoundError(role_id=role_id)
        await self.session.commit()
        logger.info(f"Role deleted: {role_id}")

    async def update_role(
            self,
            role_id: int,
            name: str | Unset = UNSET,
            description: str | Unset | None = UNSET,
    ) -> Role:
        logger.info(f"Updating role: {role_id}")
        passed_args = locals()
        role = await self.get_role(role_id)
        allowed_fields = {"name", "description"}
        for field in allowed_fields:
            value = passed_args.get(field)
            if not isinstance(value, Unset):
                setattr(role, field, value)
        async with handle_role_integrity(name=role.name, description=role.description):
            await self.session.commit()
        await self.session.refresh(role)
        logger.info(f"Role updated: {role_id}")
        return role

    async def update_permissions(
            self,
            role_id: int,
            set_data: list[dict[str, int | PolicyEffectEnum]],
            remove_ids: Sequence[int],
    ) -> Sequence[RolePermission]:
        logger.info(f"Updating permissions for role: {role_id}")
        async with handle_role_permission_integrity():
            not_deleted = await self.role_repository.remove_permissions(role_id=role_id, remove_ids=remove_ids)
            if not_deleted:
                raise PermissionsNotFoundError(permission_ids=not_deleted)
            await self.role_repository.upsert_permissions(set_data=set_data)
            await self.session.commit()
        logger.info(f"Permissions updated for role: {role_id}")
        return await self.role_repository.get_permissions(role_id=role_id)

    async def get_permissions(self, role_id: int, page: int, size: int) -> Sequence[RolePermission]:
        logger.info(f"Getting permissions for role: {role_id}, page: {page}, size: {size}")
        return await self.role_repository.list_permissions(role_id=role_id, skip=(page - 1) * size, limit=size)
