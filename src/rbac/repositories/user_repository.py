from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.models import User
from rbac.types import UserPatch
from rbac.utils import BaseRepository


class UserRepository(BaseRepository[User]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, User)

    async def create_user(
            self,
            username: str,
            password_hash: str,
    ) -> User:
        statement = (
            insert(User)
            .values(
                username=username,
                password_hash=password_hash,
            )
            .returning(User)
        )
        result = await self.session.execute(statement)
        return result.scalar_one()

    async def update_user(
            self,
            user_id: int,
            user_patch: UserPatch,
    ) -> User:
        statement = (
            update(User)
            .where(User.id == user_id)
            .values(**user_patch)
            .returning(User)
        )
        result = await self.session.execute(statement)
        return result.scalar_one()

    async def get_by_username(self, username: str) -> User | None:
        statement = (
            select(User)
            .where(User.username == username)
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()
