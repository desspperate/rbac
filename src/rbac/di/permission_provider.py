from dishka import Provider, Scope, provide
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.repositories import PermissionRepository
from rbac.services import PermissionService


class PermissionProvider(Provider):
    @provide(scope=Scope.REQUEST)
    def get_permission_service(
            self,
            session: AsyncSession,
            permission_repository: PermissionRepository,
    ) -> PermissionService:
        return PermissionService(session=session, permission_repository=permission_repository)

    @provide(scope=Scope.REQUEST)
    def get_permission_repository(self, session: AsyncSession) -> PermissionRepository:
        return PermissionRepository(session=session)
