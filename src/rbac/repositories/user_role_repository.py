from collections.abc import Sequence

from loguru import logger
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.models import UserRole
from rbac.types import UserRoleType
from rbac.utils import BaseRepository


class UserRoleRepository(BaseRepository[UserRole]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session=session, model=UserRole)

    async def upsert_user_roles(self, set_data: Sequence[UserRoleType]) -> None:
        if not set_data:
            logger.warning("No roles provided to upsert user roles")
            return
        stmt = pg_insert(UserRole).values(set_data)
        stmt = stmt.on_conflict_do_update(
            constraint=UserRole.UQ_USER_ROLE_USER_ROLE,
            set_={"effect": stmt.excluded.effect},
        )
        await self.session.execute(stmt)

    async def remove_user_roles(self, user_id: int, remove_ids: Sequence[int]) -> Sequence[int]:
        if not remove_ids:
            logger.warning("No roles provided to remove user roles")
            return []
        statement = (
            delete(UserRole)
            .where(
                UserRole.user_id == user_id,
                UserRole.role_id.in_(remove_ids),
            )
            .returning(UserRole.role_id)
        )
        result = await self.session.execute(statement)
        removed_ids = result.scalars().all()
        return list(set(remove_ids) - set(removed_ids))

    async def get_user_roles(self, user_id: int) -> Sequence[UserRole]:
        statement = select(UserRole).where(UserRole.user_id == user_id)
        result = await self.session.execute(statement)
        return result.scalars().all()

