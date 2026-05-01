from collections.abc import Sequence

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.models import Permission
from rbac.services import PermissionService
from rbac.types import PermissionPatch


class PermissionAction:
    def __init__(
            self,
            session: AsyncSession,
            permission_service: PermissionService,
    ) -> None:
        self.session = session
        self.permission_service = permission_service

    async def get_permissions(self, page: int, size: int) -> tuple[Sequence[Permission], int]:
        result = await self.permission_service.get_permissions(page=page, size=size)
        logger.info(f"Found {len(result[0])} permissions")
        return result

    async def get_permission(self, permission_id: int) -> Permission:
        permission = await self.permission_service.get_permission(permission_id=permission_id)
        logger.info(f"Found permission: {permission_id}")
        return permission

    async def create_permission(self, codename: str, description: str | None) -> Permission:
        permission = await self.permission_service.create_permission(
            codename=codename,
            description=description,
        )
        await self.session.commit()
        logger.info(f"Created permission: id={permission.id}, codename='{codename}'")
        return permission

    async def delete_permission(self, permission_id: int) -> None:
        permission = await self.permission_service.delete_permission(permission_id=permission_id)
        await self.session.commit()
        logger.info(f"Permission deleted: {permission_id}")
        return permission

    async def update_permission(
            self,
            permission_id: int,
            permission_patch: PermissionPatch,
    ) -> Permission:
        permission = await self.permission_service.update_permission(
            permission_id=permission_id,
            permission_patch=permission_patch,
        )
        await self.session.commit()
        logger.info(f"Permission updated: {permission_id}")
        return permission
