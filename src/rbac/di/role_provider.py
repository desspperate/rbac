from dishka import Provider, Scope, provide
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.repositories import RoleRepository
from rbac.services import RoleService


class RoleProvider(Provider):
    @provide(scope=Scope.REQUEST)
    def get_role_service(self, session: AsyncSession, role_repository: RoleRepository) -> RoleService:
        return RoleService(session=session, role_repository=role_repository)

    @provide(scope=Scope.REQUEST)
    def get_role_repository(self, session: AsyncSession) -> RoleRepository:
        return RoleRepository(session=session)
