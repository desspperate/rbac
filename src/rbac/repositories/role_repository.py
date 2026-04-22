from collections.abc import Sequence

from loguru import logger
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.enums import PolicyEffectEnum
from rbac.models import Role, RolePermission
from rbac.utils import BaseRepository


class RoleRepository(BaseRepository[Role]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Role)

    async def create_role(self, name: str, description: str | None) -> Role:
        new_role = Role(
            name=name,
            description=description,
        )
        self.add(new_role)
        await self.session.flush()
        await self.session.refresh(new_role)
        return new_role

    async def remove_permissions(self, role_id: int, remove_ids: Sequence[int]) -> Sequence[int]:
        if not remove_ids:
            logger.warning("No permissions provided to remove role permissions")
            return []
        statement = (
            delete(RolePermission)
            .where(
                RolePermission.role_id == role_id,
                RolePermission.permission_id.in_(remove_ids),
            )
            .returning(RolePermission.permission_id)
        )
        result = await self.session.execute(statement)
        removed_ids = result.scalars().all()
        return list(set(remove_ids) - set(removed_ids))

    async def upsert_permissions(self, set_data: Sequence[dict[str, int | PolicyEffectEnum]]) -> None:
        if not set_data:
            logger.warning("No permissions provided to upsert role permissions")
            return
        stmt = pg_insert(RolePermission).values(set_data)
        stmt = stmt.on_conflict_do_update(
            constraint=RolePermission.UQ_ROLE_PERMISSION_ROLE_PERMISSION,
            set_={"effect": stmt.excluded.effect},
        )
        await self.session.execute(stmt)

    async def get_permissions(self, role_id: int) -> Sequence[RolePermission]:
        statement = (
            select(RolePermission)
            .where(RolePermission.role_id == role_id)
        )
        result = await self.session.execute(statement)
        return result.scalars().all()

    async def list_permissions(self, role_id: int, skip: int, limit: int) -> Sequence[RolePermission]:
        statement = (
            select(RolePermission)
            .where(RolePermission.role_id == role_id)
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(statement)
        return result.scalars().all()
