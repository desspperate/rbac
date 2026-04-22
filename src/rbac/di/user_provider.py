from dishka import Provider, Scope, provide
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.repositories import UserRepository
from rbac.services import UserService


class UserProvider(Provider):
    @provide(scope=Scope.REQUEST)
    def get_user_service(self, session: AsyncSession, user_repository: UserRepository) -> UserService:
        return UserService(session=session, user_repository=user_repository)

    @provide(scope=Scope.REQUEST)
    def get_user_repository(self, session: AsyncSession) -> UserRepository:
        return UserRepository(session=session)
