from collections.abc import Sequence

from loguru import logger
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.models import UserPermission
from rbac.types import UserPermissionType
from rbac.utils import BaseRepository


class UserPermissionRepository(BaseRepository[UserPermission]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session=session, model=UserPermission)

    async def upsert_user_permissions(self, set_data: Sequence[UserPermissionType]) -> None:
        if not set_data:
            logger.warning("No permissions provided to upsert user permissions")
            return
        stmt = pg_insert(UserPermission).values(set_data)
        stmt = stmt.on_conflict_do_update(
            constraint=UserPermission.UQ_USER_PERMISSION_USER_PERMISSION,
            set_={"effect": stmt.excluded.effect},
        )
        await self.session.execute(stmt)

    async def remove_user_permissions(self, user_id: int, remove_ids: Sequence[int]) -> Sequence[int]:
        if not remove_ids:
            logger.warning("No permissions provided to remove user permissions")
            return []
        statement = (
            delete(UserPermission)
            .where(
                UserPermission.user_id == user_id,
                UserPermission.permission_id.in_(remove_ids),
            )
            .returning(UserPermission.permission_id)
        )
        result = await self.session.execute(statement)
        removed_ids = result.scalars().all()
        return list(set(remove_ids) - set(removed_ids))

    async def get_user_permissions(self, user_id: int) -> Sequence[UserPermission]:
        statement = select(UserPermission).where(UserPermission.user_id == user_id)
        result = await self.session.execute(statement)
        return result.scalars().all()
