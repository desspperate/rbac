
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.models import User
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
