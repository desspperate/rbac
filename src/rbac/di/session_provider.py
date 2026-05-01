from dishka import Provider, Scope, provide
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.actions import SessionAction
from rbac.repositories import SessionRepository
from rbac.services import SessionService


class SessionProvider(Provider):
    @provide(scope=Scope.REQUEST)
    def get_session_repository(self, session: AsyncSession) -> SessionRepository:
        return SessionRepository(session=session)

    @provide(scope=Scope.REQUEST)
    def get_session_service(self, session_repository: SessionRepository) -> SessionService:
        return SessionService(session_repository=session_repository)

    @provide(scope=Scope.REQUEST)
    def get_session_action(
            self,
            session: AsyncSession,
            session_service: SessionService,
    ) -> SessionAction:
        return SessionAction(
            session=session,
            session_service=session_service,
        )
