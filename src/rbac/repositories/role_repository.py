from sqlalchemy import insert, update
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.models import Role
from rbac.types import RolePatch
from rbac.utils import BaseRepository


class RoleRepository(BaseRepository[Role]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Role)

    async def create_role(self, name: str, description: str | None) -> Role:
        statement = (
            insert(Role)
            .values(
                name=name,
                description=description,
            )
            .returning(Role)
        )
        result = await self.session.execute(statement)
        return result.scalar_one()

    async def update_role(self, role_id: int, role_patch: RolePatch) -> Role:
        statement = (
            update(Role)
            .where(Role.id == role_id)
            .values(**role_patch)
            .returning(Role)
        )
        result = await self.session.execute(statement)
        return result.scalar_one()
