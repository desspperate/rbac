from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager

from asyncpg.exceptions import CheckViolationError, NotNullViolationError, UniqueViolationError
from loguru import logger
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.constants import RBACConstants
from rbac.errors import (
    PermissionCodenameConflictError,
    PermissionCodenameInvalidError,
    PermissionCodenameNotNullError,
    PermissionDescriptionInvalidError,
    PermissionNotFoundError,
    UnhandledIntegrityError,
)
from rbac.models import Permission
from rbac.repositories import PermissionRepository
from rbac.utils import UNSET, Unset, get_asyncpg_error


@asynccontextmanager
async def handle_permission_integrity(codename: str | None, description: str | None) -> AsyncIterator[None]:
    try:
        yield
    except IntegrityError as e:
        asyncpg_error = get_asyncpg_error(e)
        if asyncpg_error is None:
            raise UnhandledIntegrityError from e

        if isinstance(asyncpg_error, CheckViolationError | UniqueViolationError):
            constraint = getattr(asyncpg_error, "constraint_name", None)
            if not isinstance(constraint, str):
                raise UnhandledIntegrityError from e

            if constraint == Permission.CK_PERMISSION_CODENAME_PATTERN and isinstance(codename, str):
                raise PermissionCodenameInvalidError(
                    codename=codename,
                    pattern=RBACConstants.PERMISSION_CODENAME_PATTERN,
                ) from e
            if constraint == Permission.CK_PERMISSION_DESCRIPTION_PATTERN and isinstance(description, str):
                raise PermissionDescriptionInvalidError(
                    description=description,
                    pattern=RBACConstants.DESCRIPTION_PATTERN,
                ) from e
            if constraint == Permission.UQ_PERMISSION_CODENAME and isinstance(codename, str):
                raise PermissionCodenameConflictError(codename=codename) from e
        elif isinstance(asyncpg_error, NotNullViolationError):
            column = getattr(asyncpg_error, "column_name", None)
            if not isinstance(column, str):
                raise UnhandledIntegrityError from e

            if column == "codename":
                raise PermissionCodenameNotNullError from e

        raise UnhandledIntegrityError from e


class PermissionService:
    def __init__(
            self,
            session: AsyncSession,
            permission_repository: PermissionRepository,
    ) -> None:
        self.session = session
        self.permission_repository = permission_repository

    async def create_permission(self, codename: str, description: str | None) -> Permission:
        logger.info(f"Creating permission: '{codename}'")
        async with handle_permission_integrity(codename=codename, description=description):
            permission = await self.permission_repository.create_permission(
                codename=codename,
                description=description,
            )
        await self.session.commit()
        logger.info(f"Permission created: '{codename}'")
        return permission

    async def get_permissions(self, page: int, size: int) -> Sequence[Permission]:
        logger.info(f"Getting permissions for page: {page}, size: {size}")
        return await self.permission_repository.list_all(skip=(page - 1) * size, limit=size)

    async def get_permission(self, permission_id: int) -> Permission:
        logger.info(f"Getting permission: {permission_id}")
        if (permission := await self.permission_repository.get_by_id(permission_id)) is None:
            raise PermissionNotFoundError(permission_id=permission_id)
        return permission

    async def delete_permission(self, permission_id: int) -> None:
        logger.info(f"Deleting permission: {permission_id}")
        deleted = await self.permission_repository.delete_by_id(permission_id)
        if not deleted:
            raise PermissionNotFoundError(permission_id=permission_id)
        await self.session.commit()
        logger.info(f"Permission deleted: {permission_id}")

    async def update_permission(
            self,
            permission_id: int,
            codename: str | Unset = UNSET,
            description: str | Unset | None = UNSET,
    ) -> Permission:
        logger.info(f"Updating permission: {permission_id}")
        passed_args = locals()
        permission = await self.get_permission(permission_id)
        allowed_fields = {"codename", "description"}
        for field in allowed_fields:
            value = passed_args.get(field)
            if not isinstance(value, Unset):
                setattr(permission, field, value)
        async with handle_permission_integrity(codename=permission.codename, description=permission.description):
            await self.session.commit()
        await self.session.refresh(permission)
        logger.info(f"Permission updated: {permission_id}")
        return permission
