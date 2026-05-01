from sqlalchemy import insert, update
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.models import Permission
from rbac.types import PermissionPatch
from rbac.utils import BaseRepository


class PermissionRepository(BaseRepository[Permission]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Permission)

    async def create_permission(self, codename: str, description: str | None) -> Permission:
        statement = (
            insert(Permission)
            .values(
                codename=codename,
                description=description,
            )
            .returning(Permission)
        )
        result = await self.session.execute(statement)
        return result.scalar_one()

    async def update_permission(self, permission_id: int, permission_patch: PermissionPatch) -> Permission:
        statement = (
            update(Permission)
            .where(Permission.id == permission_id)
            .values(**permission_patch)
            .returning(Permission)
        )
        result = await self.session.execute(statement)
        return result.scalar_one()
