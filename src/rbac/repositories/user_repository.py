from collections.abc import Sequence

from loguru import logger
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.enums import PolicyEffectEnum
from rbac.models import User, UserPermission, UserRole
from rbac.utils import BaseRepository


class UserRepository(BaseRepository[User]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, User)

    async def create_user(
            self,
            username: str,
            password_hash: str,
    ) -> User:
        new_user = User(
            username=username,
            password_hash=password_hash,
        )
        self.add(new_user)
        await self.session.flush()
        await self.session.refresh(new_user)
        return new_user

    async def remove_roles(self, user_id: int, remove_ids: Sequence[int]) -> Sequence[int]:
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

    async def upsert_roles(self, set_data: Sequence[dict[str, int | PolicyEffectEnum]]) -> None:
        if not set_data:
            logger.warning("No roles provided to upsert user roles")
            return
        stmt = pg_insert(UserRole).values(set_data)
        stmt = stmt.on_conflict_do_update(
            constraint=UserRole.UQ_USER_ROLE_USER_ROLE,
            set_={"effect": stmt.excluded.effect},
        )
        await self.session.execute(stmt)

    async def get_roles(self, user_id: int) -> Sequence[UserRole]:
        statement = select(UserRole).where(UserRole.user_id == user_id)
        result = await self.session.execute(statement)
        return result.scalars().all()

    async def list_roles(self, user_id: int, skip: int, limit: int) -> Sequence[UserRole]:
        statement = (
            select(UserRole)
            .where(UserRole.user_id == user_id)
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(statement)
        return result.scalars().all()

    async def remove_permissions(self, user_id: int, remove_ids: Sequence[int]) -> Sequence[int]:
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

    async def upsert_permissions(self, set_data: Sequence[dict[str, int | PolicyEffectEnum]]) -> None:
        if not set_data:
            logger.warning("No permissions provided to upsert user permissions")
            return
        stmt = pg_insert(UserPermission).values(set_data)
        stmt = stmt.on_conflict_do_update(
            constraint=UserPermission.UQ_USER_PERMISSION_USER_PERMISSION,
            set_={"effect": stmt.excluded.effect},
        )
        await self.session.execute(stmt)

    async def get_permissions(self, user_id: int) -> Sequence[UserPermission]:
        statement = select(UserPermission).where(UserPermission.user_id == user_id)
        result = await self.session.execute(statement)
        return result.scalars().all()

    async def list_permissions(self, user_id: int, skip: int, limit: int) -> Sequence[UserPermission]:
        statement = (
            select(UserPermission)
            .where(UserPermission.user_id == user_id)
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(statement)
        return result.scalars().all()
