from datetime import UTC, datetime

from loguru import logger
from pydantic import SecretStr

from rbac.constants import RBACConstants
from rbac.enums import ForcedTokenStatusEnum, TokenTypeEnum
from rbac.errors import (
    InvalidCredentialsError,
    TokenExpiredError,
    TokenMismatchError,
    TokenRevokedError,
    UserNotFoundByUsernameError,
)
from rbac.models import User
from rbac.types import TokenPairType, TokenPatch
from rbac.utils import hash_token, verify_crypto_hash

from .session_service import SessionService
from .token_service import TokenService
from .user_service import UserService


class AuthService:
    def __init__(
            self,
            user_service: UserService,
            token_service: TokenService,
            session_service: SessionService,
    ) -> None:
        self.user_service = user_service
        self.token_service = token_service
        self.session_service = session_service

    async def register_user(
            self,
            username: str,
            password: SecretStr,
            user_agent: str,
            ip_address: str,
    ) -> tuple[User, TokenPairType]:
        logger.info(f"Registering user with username: {username}")
        new_user = await self.user_service.create_user(username=username, password=password)
        token_pair = await self._issue_token_pair(
            user_id=new_user.id,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        return new_user, token_pair

    async def login(
            self,
            username: str,
            password: SecretStr,
            user_agent: str,
            ip_address: str,
    ) -> tuple[User, TokenPairType]:
        logger.info(f"Logging in user with username: {username}")

        try:
            user = await self.user_service.find_by_username(username)
        except UserNotFoundByUsernameError:
            logger.warning("Trying to login user with username not found")
            user = None

        dummy_hash = RBACConstants.DUMMY_HASH
        target_hash = user.password_hash if user else dummy_hash

        is_valid = await verify_crypto_hash(
            secret=password.get_secret_value(),
            hash_string=target_hash,
        )
        if not is_valid or user is None:
            raise InvalidCredentialsError
        token_pair = await self._issue_token_pair(
            user_id=user.id,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        return user, token_pair

    async def refresh(
            self,
            access_token: SecretStr,
            refresh_token: SecretStr,
            user_agent: str,
            ip_address: str,
    ) -> TokenPairType:
        logger.info("Refreshing token pair")

        now = datetime.now(tz=UTC)

        access_token_hash = hash_token(bytes.fromhex(access_token.get_secret_value()))
        access_token_db = await self.token_service.find_by_token_hash_for_update(token_hash=access_token_hash)

        if access_token_db.forced_status is not None:
            raise TokenRevokedError
        if access_token_db.token_type != TokenTypeEnum.ACCESS:
            raise TokenMismatchError

        refresh_token_hash = hash_token(bytes.fromhex(refresh_token.get_secret_value()))
        refresh_token_db = await self.token_service.find_by_token_hash_for_update(token_hash=refresh_token_hash)

        if now > refresh_token_db.expires_at:
            raise TokenExpiredError
        if refresh_token_db.forced_status is not None:
            raise TokenRevokedError
        if refresh_token_db.token_type != TokenTypeEnum.REFRESH:
            raise TokenMismatchError
        if refresh_token_db.session_id != access_token_db.session_id:
            raise TokenMismatchError

        revoke_patch: TokenPatch = {"forced_status": ForcedTokenStatusEnum.REVOKED_DUE_TO_REFRESH}
        await self.token_service.update_token(access_token_db.id, revoke_patch)
        await self.token_service.update_token(refresh_token_db.id, revoke_patch)

        session = await self.session_service.get_session(access_token_db.session_id)
        return await self._issue_token_pair(
            user_id=session.user_id,
            user_agent=user_agent,
            ip_address=ip_address,
        )

    async def _issue_token_pair(self, user_id: int, user_agent: str, ip_address: str) -> TokenPairType:
        session = await self.session_service.create_session(
            user_id=user_id,
            forced_status=None,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        access_token = await self.token_service.create_token(
            session_id=session.id,
            token_type=TokenTypeEnum.ACCESS,
        )
        refresh_token = await self.token_service.create_token(
            session_id=session.id,
            token_type=TokenTypeEnum.REFRESH,
        )
        now = datetime.now(tz=UTC)
        return TokenPairType(
            access_token=access_token.token,
            expires_in=int((access_token.expires_at - now).total_seconds()),
            refresh_token=refresh_token.token,
            refresh_expires_in=int((refresh_token.expires_at - now).total_seconds()),
            token_type="Bearer",  # noqa: S106
        )
