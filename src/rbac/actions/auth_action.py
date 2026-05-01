from loguru import logger
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.services import AuthService
from rbac.types import TokenPairType, UserIdentityType


class AuthAction:
    def __init__(
            self,
            session: AsyncSession,
            auth_service: AuthService,
    ) -> None:
        self.session = session
        self.auth_service = auth_service

    async def register(
            self,
            username: str,
            password: SecretStr,
            user_agent: str,
            ip_address: str,
    ) -> TokenPairType:
        user, token_pair = await self.auth_service.register_user(
            username=username,
            password=password,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        await self.session.commit()
        logger.info(f"New user id={user.id} username='{username}' registered")
        return token_pair

    async def login(
            self,
            username: str,
            password: SecretStr,
            user_agent: str,
            ip_address: str,
    ) -> TokenPairType:
        user, token_pair = await self.auth_service.login(
            username=username,
            password=password,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        await self.session.commit()
        logger.info(f"User id={user.id} username='{username}' successfully logged in")
        return token_pair

    async def refresh(
            self,
            access_token: SecretStr,
            refresh_token: SecretStr,
            user_agent: str,
            ip_address: str,
    ) -> TokenPairType:
        token_pair, user_id, session_id = await self.auth_service.refresh(
            access_token=access_token,
            refresh_token=refresh_token,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        await self.session.commit()
        logger.info(f"User {user_id} refresh session {session_id} successfully")
        return token_pair

    async def get_user_identity(self, access_token: SecretStr) -> UserIdentityType:
        user_identity: UserIdentityType = await self.auth_service.get_user_identity(access_token=access_token)
        logger.info(f"Found user identity for user {user_identity["user_id"]}")
        return user_identity

    async def logout(self, access_token: SecretStr) -> None:
        logout_results = await self.auth_service.logout(access_token=access_token)
        await self.session.commit()
        logger.info(f"User logged out from session: {logout_results["session_id"]} successfully")

    async def logout_all(self, access_token: SecretStr, *, exclude_current: bool) -> None:
        logout_all_results = await self.auth_service.logout_all(
            access_token=access_token,
            exclude_current=exclude_current,
        )
        await self.session.commit()
        logger.info(f"User {logout_all_results["user_id"]} from session {logout_all_results["current_session_id"]} "
                    f"logged all out successfully")
