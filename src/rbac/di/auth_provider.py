from dishka import Provider, Scope, provide
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.actions import AuthAction
from rbac.services import AuthService, SessionService, TokenService, UserService


class AuthProvider(Provider):
    @provide(scope=Scope.REQUEST)
    def get_auth_action(self, session: AsyncSession, auth_service: AuthService) -> AuthAction:
        return AuthAction(
            session=session,
            auth_service=auth_service,
        )

    @provide(scope=Scope.REQUEST)
    def get_auth_service(
            self,
            user_service: UserService,
            token_service: TokenService,
            session_service: SessionService,
    ) -> AuthService:
        return AuthService(
            user_service=user_service,
            token_service=token_service,
            session_service=session_service,
        )
