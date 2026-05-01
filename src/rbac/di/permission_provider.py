from dishka import Provider, Scope, provide
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.actions.permission_action import PermissionAction
from rbac.repositories import PermissionRepository
from rbac.services import PermissionService


class PermissionProvider(Provider):
    @provide(scope=Scope.REQUEST)
    def get_permission_action(self, session: AsyncSession, permission_service: PermissionService) -> PermissionAction:
        return PermissionAction(session=session, permission_service=permission_service)

    @provide(scope=Scope.REQUEST)
    def get_permission_service(
            self,
            permission_repository: PermissionRepository,
    ) -> PermissionService:
        return PermissionService(permission_repository=permission_repository)

    @provide(scope=Scope.REQUEST)
    def get_permission_repository(self, session: AsyncSession) -> PermissionRepository:
        return PermissionRepository(session=session)
