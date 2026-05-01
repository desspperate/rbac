from loguru import logger
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.services import AuthService
from rbac.types import TokenPairType


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
        token_pair = await self.auth_service.refresh(
            access_token=access_token,
            refresh_token=refresh_token,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        await self.session.commit()
        logger.info("Token pair refreshed successfully")
        return token_pair
