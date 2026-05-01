import os
from datetime import UTC, datetime, timedelta

from loguru import logger
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.constants import RBACConstants
from rbac.enums import AccessTokenStatusEnum, TokenPairStatusEnum, TokenTypeEnum
from rbac.errors import (
    InvalidCredentialsError,
    SessionRevokedError,
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
    TokenSessionMismatchError,
    TokenTypeMismatchError,
    UserNotFoundByUsernameError,
)
from rbac.models import User
from rbac.repositories import AuthRepository
from rbac.types import LogoutAllResultType, LogoutResultType, TokenPairType, UserIdentityType
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
            auth_repository: AuthRepository,
            session: AsyncSession,
    ) -> None:
        self.session = session
        self.user_service = user_service
        self.token_service = token_service
        self.session_service = session_service
        self.auth_repository = auth_repository

    async def register_user(
            self,
            username: str,
            password: SecretStr,
            user_agent: str,
            ip_address: str,
    ) -> tuple[User, TokenPairType]:
        logger.info(f"Registering user with username: {username}")
        new_user = await self.user_service.create_user(username=username, password=password)
        session = await self.session_service.create_session(
            user_id=new_user.id,
            forced_status=None,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        token_pair = await self._issue_token_pair(session_id=session.id)
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

        session = await self.session_service.create_session(
            user_id=user.id,
            forced_status=None,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        token_pair = await self._issue_token_pair(session_id=session.id)
        return user, token_pair

    async def _issue_token_pair(self, session_id: int) -> TokenPairType:
        access_token = await self.token_service.create_token(
            session_id=session_id,
            token_type=TokenTypeEnum.ACCESS,
        )
        refresh_token = await self.token_service.create_token(
            session_id=session_id,
            token_type=TokenTypeEnum.REFRESH,
        )
        return TokenPairType(
            access_token=access_token.token,
            expires_in=self.get_token_remaining_seconds(expires_at=access_token.expires_at),
            refresh_token=refresh_token.token,
            refresh_expires_in=self.get_token_remaining_seconds(expires_at=refresh_token.expires_at),
            token_type="Bearer",  # noqa: S106
        )

    @staticmethod
    def get_token_remaining_seconds(expires_at: datetime) -> int:
        now = datetime.now(tz=UTC)
        return int((expires_at - now).total_seconds())

    async def refresh(
            self,
            access_token: SecretStr,
            refresh_token: SecretStr,
            user_agent: str,
            ip_address: str,
    ) -> tuple[TokenPairType, str, str]:
        """
            :returns TokenPair, user_id, session_id
        """

        logger.info("Refreshing token pair")
        access_hash = self.fetch_token_hash_from_secret(token_secret=access_token)
        refresh_hash = self.fetch_token_hash_from_secret(token_secret=refresh_token)
        access_token_ttl = self.token_service.get_token_ttl(TokenTypeEnum.ACCESS)
        refresh_token_ttl = self.token_service.get_token_ttl(TokenTypeEnum.REFRESH)

        now = datetime.now(tz=UTC)
        new_access_token = os.urandom(32)
        new_refresh_token = os.urandom(32)

        access_expires_at = now + timedelta(minutes=access_token_ttl)
        refresh_expires_at = now + timedelta(minutes=refresh_token_ttl)

        refresh_results = await self.auth_repository.refresh_session(
            access_hash=access_hash,
            refresh_hash=refresh_hash,

            new_access_hash=hash_token(new_access_token),
            new_refresh_hash=hash_token(new_refresh_token),
            access_expires_at=access_expires_at,
            refresh_expires_at=refresh_expires_at,

            user_agent=user_agent,
            ip_address=ip_address,
        )
        status = refresh_results["status"]

        if status != TokenPairStatusEnum.VALID:
            error_map = {
                TokenPairStatusEnum.ACCESS_NOT_FOUND: TokenInvalidError(token_type=TokenTypeEnum.ACCESS),
                TokenPairStatusEnum.REFRESH_NOT_FOUND: TokenInvalidError(token_type=TokenTypeEnum.REFRESH),
                TokenPairStatusEnum.ACCESS_WRONG_TYPE: TokenTypeMismatchError(token_type=TokenTypeEnum.ACCESS),
                TokenPairStatusEnum.REFRESH_WRONG_TYPE: TokenTypeMismatchError(token_type=TokenTypeEnum.REFRESH),
                TokenPairStatusEnum.SESSION_MISMATCH: TokenSessionMismatchError,
                TokenPairStatusEnum.SESSION_REVOKED: SessionRevokedError,
                TokenPairStatusEnum.ACCESS_REVOKED: TokenRevokedError(token_type=TokenTypeEnum.ACCESS),
                TokenPairStatusEnum.REFRESH_REVOKED: TokenRevokedError(token_type=TokenTypeEnum.REFRESH),
                TokenPairStatusEnum.REFRESH_EXPIRED: TokenExpiredError(token_type=TokenTypeEnum.REFRESH),
            }
            error = error_map.get(status, TokenInvalidError)
            raise error

        return (
            TokenPairType(
                access_token=new_access_token.hex(),
                refresh_token=new_refresh_token.hex(),
                expires_in=self.get_token_remaining_seconds(expires_at=access_expires_at),
                refresh_expires_in=self.get_token_remaining_seconds(expires_at=refresh_expires_at),
                token_type="Bearer",  # noqa: S106
            ),
            refresh_results["user_id"],
            refresh_results["session_id"],
        )

    async def get_user_identity(self, access_token: SecretStr) -> UserIdentityType:
        logger.info("Getting user identity")
        token_hash = self.fetch_token_hash_from_secret(token_secret=access_token)
        user_identity = await self.auth_repository.get_user_identity(token_hash=token_hash)

        if user_identity is None:
            raise TokenInvalidError

        status = user_identity["status"]
        self.handle_access_token_db_status(status=status)

        return user_identity

    async def logout(self, access_token: SecretStr) -> LogoutResultType:
        logger.info("Trying to logout session")
        token_hash = self.fetch_token_hash_from_secret(token_secret=access_token)
        logout_results = await self.auth_repository.logout(token_hash=token_hash)

        if logout_results is None:
            raise TokenInvalidError

        status = logout_results["status"]
        self.handle_access_token_db_status(status=status)

        return logout_results

    async def logout_all(self, access_token: SecretStr, *, exclude_current: bool) -> LogoutAllResultType:
        logger.info(f"Trying to logout of all user sessions (exclude_current={exclude_current})")
        token_hash = self.fetch_token_hash_from_secret(token_secret=access_token)
        logout_all_results = await self.auth_repository.logout_all(
            token_hash=token_hash,
            exclude_current=exclude_current,
        )

        if logout_all_results is None:
            raise TokenInvalidError

        status = logout_all_results["status"]
        self.handle_access_token_db_status(status=status)

        return logout_all_results

    @staticmethod
    def fetch_token_hash_from_secret(token_secret: SecretStr) -> str:
        try:
            token_hash = hash_token(token=bytes.fromhex(token_secret.get_secret_value()))
        except ValueError as e:
            raise TokenInvalidError from e
        return token_hash

    @staticmethod
    def handle_access_token_db_status(status: str) -> None:
        if status != AccessTokenStatusEnum.VALID:
            if status == AccessTokenStatusEnum.EXPIRED:
                raise TokenExpiredError(token_type=TokenTypeEnum.ACCESS)
            if status == AccessTokenStatusEnum.TOKEN_REVOKED:
                raise TokenRevokedError(token_type=TokenTypeEnum.ACCESS)
            if status == AccessTokenStatusEnum.SESSION_REVOKED:
                raise SessionRevokedError
            if status == AccessTokenStatusEnum.WRONG_TYPE:
                raise TokenTypeMismatchError(token_type=TokenTypeEnum.ACCESS)
            raise TokenInvalidError
