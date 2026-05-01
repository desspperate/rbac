from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager

from asyncpg import ForeignKeyViolationError
from asyncpg.exceptions import CheckViolationError, NotNullViolationError, UniqueViolationError
from loguru import logger
from sqlalchemy.exc import IntegrityError

from rbac.constants import RBACConstants
from rbac.errors import (
    PermissionCodenameConflictError,
    PermissionCodenameInvalidError,
    PermissionCodenameNullError,
    PermissionDescriptionInvalidError,
    PermissionNotFoundError,
    UnhandledIntegrityError,
)
from rbac.errors.permission_errors import PermissionStillReferencedError
from rbac.models import Permission, RolePermission, UserPermission
from rbac.repositories import PermissionRepository
from rbac.types import PermissionPatch
from rbac.utils import HandleIntegrityHelpers, get_asyncpg_error


@asynccontextmanager
async def handle_permission_integrity(codename: str | None, description: str | None) -> AsyncIterator[None]:
    try:
        yield
    except IntegrityError as e:
        asyncpg_error = get_asyncpg_error(e)
        if asyncpg_error is None:
            raise UnhandledIntegrityError from e

        if isinstance(asyncpg_error, CheckViolationError | UniqueViolationError | ForeignKeyViolationError):
            constraint = HandleIntegrityHelpers.get_constraint(asyncpg_error, e)

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

            if isinstance(asyncpg_error, ForeignKeyViolationError):
                _, failed_value, referrer_table = HandleIntegrityHelpers.get_details(asyncpg_error, e)

                if constraint in {
                    UserPermission.FK_USER_PERMISSION_PERMISSION_ID,
                    RolePermission.FK_ROLE_PERMISSION_PERMISSION_ID,
                }:
                     raise PermissionStillReferencedError(
                        permission_id=failed_value,
                        related_object_type=referrer_table,
                    ) from e
        elif isinstance(asyncpg_error, NotNullViolationError):
            column = HandleIntegrityHelpers.get_column(asyncpg_error, e)

            if column == "codename":
                raise PermissionCodenameNullError from e

        raise UnhandledIntegrityError from e


class PermissionService:
    def __init__(
            self,
            permission_repository: PermissionRepository,
    ) -> None:
        self.permission_repository = permission_repository

    async def create_permission(self, codename: str, description: str | None) -> Permission:
        logger.info(f"Creating permission: '{codename}'")
        async with handle_permission_integrity(codename=codename, description=description):
            return await self.permission_repository.create_permission(
                codename=codename,
                description=description,
            )

    async def get_permissions(self, page: int, size: int) -> tuple[Sequence[Permission], int]:
        logger.info(f"Getting permissions for page: {page}, size: {size}")
        return await self.permission_repository.list_all(skip=(page - 1) * size, limit=size)

    async def get_permission(self, permission_id: int) -> Permission:
        logger.info(f"Getting permission: {permission_id}")
        if (permission := await self.permission_repository.get_by_id(permission_id)) is None:
            raise PermissionNotFoundError(permission_id=permission_id)
        return permission

    async def delete_permission(self, permission_id: int) -> None:
        logger.info(f"Deleting permission: {permission_id}")
        async with handle_permission_integrity(codename=None, description=None):
            deleted = await self.permission_repository.delete_by_id(permission_id)
        if not deleted:
            raise PermissionNotFoundError(permission_id=permission_id)
        logger.info(f"Permission deleted: {permission_id}")

    async def update_permission(
            self,
            permission_id: int,
            permission_patch: PermissionPatch,
    ) -> Permission:
        logger.info(f"Updating permission: {permission_id}")
        async with handle_permission_integrity(
                codename=permission_patch.get("codename"),
                description=permission_patch.get("description"),
        ):
            return await self.permission_repository.update_permission(
                permission_id=permission_id,
                permission_patch=permission_patch,
            )
