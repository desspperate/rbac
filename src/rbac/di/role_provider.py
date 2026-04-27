from dishka import Provider, Scope, provide
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.repositories import RolePermissionRepository, RoleRepository
from rbac.services import RoleService


class RoleProvider(Provider):
    @provide(scope=Scope.REQUEST)
    def get_role_service(
            self,
            session: AsyncSession,
            role_repository: RoleRepository,
            role_permission_repository: RolePermissionRepository,
    ) -> RoleService:
        return RoleService(
            session=session,
            role_repository=role_repository,
            role_permission_repository=role_permission_repository,
        )

    @provide(scope=Scope.REQUEST)
    def get_role_permission_repository(self, session: AsyncSession) -> RolePermissionRepository:
        return RolePermissionRepository(session=session)

    @provide(scope=Scope.REQUEST)
    def get_role_repository(self, session: AsyncSession) -> RoleRepository:
        return RoleRepository(session=session)
