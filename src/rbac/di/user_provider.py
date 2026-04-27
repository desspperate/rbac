from dishka import Provider, Scope, provide
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.repositories import UserPermissionRepository, UserRepository, UserRoleRepository
from rbac.services import UserService


class UserProvider(Provider):
    @provide(scope=Scope.REQUEST)
    def get_user_service(
            self,
            session: AsyncSession,
            user_repository: UserRepository,
            user_role_repository: UserRoleRepository,
            user_permission_repository: UserPermissionRepository,
    ) -> UserService:
        return UserService(
            session=session,
            user_repository=user_repository,
            user_role_repository=user_role_repository,
            user_permission_repository=user_permission_repository,
        )

    @provide(scope=Scope.REQUEST)
    def get_user_role_repository(
            self,
            session: AsyncSession,
    ) -> UserRoleRepository:
        return UserRoleRepository(session=session)

    @provide(scope=Scope.REQUEST)
    def get_user_permission_repository(
            self,
            session: AsyncSession,
    ) -> UserPermissionRepository:
        return UserPermissionRepository(session=session)

    @provide(scope=Scope.REQUEST)
    def get_user_repository(self, session: AsyncSession) -> UserRepository:
        return UserRepository(session=session)
