from collections.abc import Sequence

from loguru import logger
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.enums import PolicyEffectEnum
from rbac.models import RolePermission
from rbac.utils import BaseRepository


class RolePermissionRepository(BaseRepository[RolePermission]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session=session, model=RolePermission)

    async def remove_role_permissions(self, role_id: int, remove_ids: Sequence[int]) -> Sequence[int]:
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

    async def upsert_role_permissions(self, set_data: Sequence[dict[str, int | PolicyEffectEnum]]) -> None:
        if not set_data:
            logger.warning("No permissions provided to upsert role permissions")
            return
        stmt = pg_insert(RolePermission).values(set_data)
        stmt = stmt.on_conflict_do_update(
            constraint=RolePermission.UQ_ROLE_PERMISSION_ROLE_PERMISSION,
            set_={"effect": stmt.excluded.effect},
        )
        await self.session.execute(stmt)

    async def get_role_permissions(self, role_id: int) -> Sequence[RolePermission]:
        statement = (
            select(RolePermission)
            .where(RolePermission.role_id == role_id)
        )
        result = await self.session.execute(statement)
        return result.scalars().all()
