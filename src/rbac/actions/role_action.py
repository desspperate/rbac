from collections.abc import Sequence

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.models import Role, RolePermission
from rbac.services import RoleService
from rbac.types import RolePatch, RolePermissionsPatch


class RoleAction:
    def __init__(
            self,
            session: AsyncSession,
            role_service: RoleService,
    ) -> None:
        self.role_service = role_service
        self.session = session

    async def get_roles(self, page: int, size: int) -> tuple[Sequence[Role], int]:
        result = await self.role_service.get_roles(page=page, size=size)
        logger.info(f"Found {len(result[0])} roles")
        return result

    async def get_role(self, role_id: int) -> Role:
        role = await self.role_service.get_role(role_id=role_id)
        logger.info(f"Found role with: id={role.id}, name={role.name}")
        return role

    async def create_role(self, name: str, description: str | None) -> Role:
        role = await self.role_service.create_role(name=name, description=description)
        await self.session.commit()
        logger.info(f"Role created: id={role.id}, username='{name}'")
        return role

    async def delete_role(self, role_id: int) -> None:
        await self.role_service.delete_role(role_id=role_id)
        await self.session.commit()
        logger.info(f"Role deleted: {role_id}")

    async def update_role(
            self,
            role_id: int,
            role_patch: RolePatch,
    ) -> Role:
        role = await self.role_service.update_role(role_id=role_id, role_patch=role_patch)
        await self.session.commit()
        logger.info(f"Role updated: {role_id}")
        return role

    async def update_role_permissions(
            self,
            role_id: int,
            role_permissions_patch: RolePermissionsPatch,
    ) -> Sequence[RolePermission]:
        role_permissions = await self.role_service.update_permissions(
            role_id=role_id,
            role_permissions_patch=role_permissions_patch,
        )
        await self.session.commit()
        logger.info(f"Role permissions updated: {role_id}")
        return role_permissions

    async def get_role_permissions(
            self,
            role_id: int,
            page: int,
            size: int,
    ) -> tuple[Sequence[RolePermission], int]:
        result = await self.role_service.get_permissions(role_id=role_id, page=page, size=size)
        logger.info(f"Found {len(result[0])} permissions")
        return result
