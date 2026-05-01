from dishka import Provider, Scope, provide
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.actions import TokenAction
from rbac.configs import RBACConfig
from rbac.repositories import TokenRepository
from rbac.services.token_service import TokenService


class TokenProvider(Provider):
    @provide(scope=Scope.REQUEST)
    def get_token_action(
            self,
            session: AsyncSession,
            token_service: TokenService,
    ) -> TokenAction:
        return TokenAction(
            session=session,
            token_service=token_service,
        )

    @provide(scope=Scope.REQUEST)
    def get_token_repository(self, session: AsyncSession) -> TokenRepository:
        return TokenRepository(session=session)

    @provide(scope=Scope.REQUEST)
    def get_token_service(
            self,
            token_repository: TokenRepository,
            rbac_config: RBACConfig,
    ) -> TokenService:
        return TokenService(
            token_repository=token_repository,
            rbac_config=rbac_config,
        )
