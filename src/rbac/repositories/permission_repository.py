from sqlalchemy.ext.asyncio import AsyncSession

from rbac.models import Permission
from rbac.utils import BaseRepository


class PermissionRepository(BaseRepository[Permission]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Permission)

    async def create_permission(self, codename: str, description: str | None) -> Permission:
        new_permission = Permission(
            codename=codename,
            description=description,
        )
        self.add(new_permission)
        await self.session.flush()
        await self.session.refresh(new_permission)
        return new_permission
