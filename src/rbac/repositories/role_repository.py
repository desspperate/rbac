
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.models import Role
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
