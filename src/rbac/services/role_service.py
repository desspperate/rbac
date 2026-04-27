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
    RoleStillReferencedError,
    UnhandledIntegrityError,
)
from rbac.models import Role, RolePermission, UserRole
from rbac.repositories import RolePermissionRepository, RoleRepository
from rbac.utils import UNSET, HandleIntegrityHelpers, Unset, get_asyncpg_error


@asynccontextmanager
async def handle_role_integrity(name: str | None, description: str | None) -> AsyncIterator[None]:
    try:
        yield
    except IntegrityError as e:
        asyncpg_error = get_asyncpg_error(e)
        if asyncpg_error is None:
            raise UnhandledIntegrityError from e

        if isinstance(asyncpg_error, UniqueViolationError | CheckViolationError | ForeignKeyViolationError):
            constraint = HandleIntegrityHelpers.get_constraint(asyncpg_error, e)

            if constraint == Role.UQ_ROLE_NAME and isinstance(name, str):
                raise RoleNameAlreadyExistError(name=name) from e
            if constraint == Role.CK_ROLE_NAME_PATTERN and isinstance(name, str):
                raise RoleNameInvalidError(name=name, pattern=RBACConstants.ROLE_NAME_PATTERN) from e
            if constraint == Role.CK_ROLE_DESCRIPTION_PATTERN and isinstance(description, str):
                raise RoleDescriptionInvalidError(
                    description=description,
                    pattern=RBACConstants.DESCRIPTION_PATTERN,
                ) from e

            if isinstance(asyncpg_error, ForeignKeyViolationError):
                _, failed_value, referrer_table = HandleIntegrityHelpers.get_details(asyncpg_error, e)

                if constraint in {
                    RolePermission.FK_ROLE_PERMISSION_ROLE_ID,
                    UserRole.FK_USER_ROLE_ROLE_ID,
                }:
                    raise RoleStillReferencedError(
                        role_id=failed_value,
                        related_object_type=referrer_table,
                    ) from e
        elif isinstance(asyncpg_error, NotNullViolationError):
            column = HandleIntegrityHelpers.get_column(asyncpg_error, e)

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

        constraint = HandleIntegrityHelpers.get_constraint(asyncpg_error, e)

        if isinstance(asyncpg_error, ForeignKeyViolationError):
            _, failed_value, _ = HandleIntegrityHelpers.get_details(asyncpg_error, e)

            if constraint == RolePermission.FK_ROLE_PERMISSION_ROLE_ID:
                raise RoleNotFoundError(role_id=failed_value) from e
            elif constraint == RolePermission.FK_ROLE_PERMISSION_PERMISSION_ID:
                raise PermissionNotFoundError(permission_id=failed_value) from e

        raise UnhandledIntegrityError from e


class RoleService:
    def __init__(
            self,
            session: AsyncSession,
            role_repository: RoleRepository,
            role_permission_repository: RolePermissionRepository,
    ) -> None:
        self.session = session
        self.role_repository = role_repository
        self.role_permission_repository = role_permission_repository

    async def get_roles(self, page: int, size: int) -> tuple[Sequence[Role], int]:
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
        async with handle_role_integrity(name=None, description=None):
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
        role = await self.get_role(role_id)
        allowed_fields = {
            "name": name,
            "description": description,
        }
        for field, value in allowed_fields.items():
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
            not_deleted = await self.role_permission_repository.remove_role_permissions(
                role_id=role_id,
                remove_ids=remove_ids,
            )
            if not_deleted:
                raise PermissionsNotFoundError(permission_ids=not_deleted)
            await self.role_permission_repository.upsert_role_permissions(set_data=set_data)
            await self.session.commit()
        logger.info(f"Permissions updated for role: {role_id}")
        return await self.role_permission_repository.get_role_permissions(role_id=role_id)

    async def get_permissions(self, role_id: int, page: int, size: int) -> tuple[Sequence[RolePermission], int]:
        logger.info(f"Getting permissions for role: {role_id}, page: {page}, size: {size}")
        return await self.role_permission_repository.list_all(
            skip=(page - 1) * size,
            limit=size,
            role_id=role_id,
        )
