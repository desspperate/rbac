import hashlib
import os
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

from asyncpg import ForeignKeyViolationError, NotNullViolationError, UniqueViolationError
from loguru import logger
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.configs import RBACConfig
from rbac.enums import ForcedTokenStatusEnum, TokenTypeEnum
from rbac.errors import (
    TokenExpiresAtNullError,
    TokenNotFoundError,
    TokenTokenHashAlreadyExistError,
    TokenTokenHashNullError,
    TokenTokenTypeNullError,
    TokenUserIdNullError,
    UnhandledIntegrityError,
    UnsupportedTokenTypeError,
    UserNotFoundError,
)
from rbac.models import Token
from rbac.repositories import TokenRepository
from rbac.schemas import TokenPrivateRead
from rbac.utils import UNSET, HandleIntegrityHelpers, Unset, get_asyncpg_error


@asynccontextmanager
async def handle_token_integrity(token_hash: str | None) -> AsyncIterator[None]:
    try:
        yield
    except IntegrityError as e:
        asyncpg_error = get_asyncpg_error(e)
        if asyncpg_error is None:
            raise UnhandledIntegrityError from e

        if isinstance(asyncpg_error, UniqueViolationError | ForeignKeyViolationError):
            constraint = HandleIntegrityHelpers.get_constraint(asyncpg_error, e)

            if constraint == Token.UQ_TOKEN_TOKEN_HASH and isinstance(token_hash, str):
                raise TokenTokenHashAlreadyExistError(token_hash=token_hash) from e

            if isinstance(asyncpg_error, ForeignKeyViolationError):
                _, failed_value, _ = HandleIntegrityHelpers.get_details(asyncpg_error, e)

                if constraint == Token.FK_TOKEN_USER_ID:
                    raise UserNotFoundError(user_id=failed_value) from e
        elif isinstance(asyncpg_error, NotNullViolationError):
            column = HandleIntegrityHelpers.get_column(asyncpg_error, e)

            error_map = {
                "user_id": TokenUserIdNullError,
                "token_hash": TokenTokenHashNullError,
                "token_type": TokenTokenTypeNullError,
                "expires_at": TokenExpiresAtNullError,
            }
            error = error_map[column]

            raise error from e

        raise UnhandledIntegrityError from e


class TokenService:
    def __init__(self, token_repository: TokenRepository, session: AsyncSession, rbac_config: RBACConfig) -> None:
        self.token_repository = token_repository
        self.session = session
        self.rbac_config = rbac_config

    @staticmethod
    def _hash_token(token: bytes | str) -> str:
        if isinstance(token, str):
            token_bytes: bytes = token.encode()
        else:
            token_bytes = token
        return hashlib.sha256(token_bytes).hexdigest()

    def get_token_ttl(self, token_type: TokenTypeEnum) -> int:
        ttl_map = {
            TokenTypeEnum.REFRESH: self.rbac_config.REFRESH_TOKEN_EXPIRE_MINUTES,
            TokenTypeEnum.ACCESS: self.rbac_config.ACCESS_TOKEN_EXPIRE_MINUTES,
        }
        try:
            return ttl_map[token_type]
        except KeyError as e:
            raise UnsupportedTokenTypeError(token_type) from e

    async def get_token(self, token_id: int) -> Token:
        logger.info(f"Getting token: {token_id}")
        if (token := await self.token_repository.get_by_id(token_id)) is None:
            raise TokenNotFoundError(token_id)
        return token

    async def get_tokens(self, page: int, size: int) -> tuple[Sequence[Token], int]:
        logger.info(f"Getting tokens for page: {page}, size: {size}")
        return await self.token_repository.list_all(skip=(page - 1) * size, limit=size)

    async def create_token(
            self,
            user_id: int,
            token_type: TokenTypeEnum,
            provided_token: bytes | None,
            forced_status: ForcedTokenStatusEnum | None,
            expires_at_: datetime | None,
    ) -> TokenPrivateRead:
        logger.info(f"Creating token '{token_type.name}' for user '{user_id}'")
        token_value: bytes = os.urandom(32) if provided_token is None else provided_token
        token_hash = self._hash_token(token_value)
        token_ttl = self.get_token_ttl(token_type=token_type)

        async with handle_token_integrity(token_hash=token_hash):
            token_db = await self.token_repository.create_token(
                user_id=user_id,
                token_hash=token_hash,
                token_type=token_type,
                forced_status=forced_status,
                expires_at=(
                    expires_at_ if expires_at_ is not None
                    else datetime.now(tz=UTC) + timedelta(minutes=token_ttl)
                ),
            )
            await self.session.commit()
        logger.info(f"Created token '{token_type.name}' for user '{user_id}'")
        return TokenPrivateRead(
            user_id=token_db.user_id,
            token_hash=token_db.token_hash,
            token_type=token_db.token_type,
            forced_status=token_db.forced_status,
            expires_at=token_db.expires_at,
            id=token_db.id,
            created_at=token_db.created_at,
            updated_at=token_db.updated_at,
            token=token_value.hex(),
        )

    async def delete_token(self, token_id: int) -> None:
        logger.info(f"Deleting token: {token_id}")
        async with handle_token_integrity(token_hash=None):
            deleted = await self.token_repository.delete_by_id(obj_id=token_id)
        if not deleted:
            raise TokenNotFoundError(token_id=token_id)
        await self.session.commit()
        logger.info(f"Deleted token: {token_id}")

    async def update_token(  # noqa: PLR0913
            self,
            token_id: int,
            token_type: TokenTypeEnum | Unset = UNSET,
            expires_at: datetime | Unset = UNSET,
            user_id: int | Unset = UNSET,
            token_value: bytes | Unset = UNSET,
            forced_status: ForcedTokenStatusEnum | None | Unset = UNSET,
    ) -> Token:
        logger.info(f"Updating token: {token_id}")
        token_db = await self.get_token(token_id=token_id)
        updates = {
            "token_type": token_type,
            "expires_at": expires_at,
            "user_id": user_id,
            "forced_status": forced_status,
        }
        for field, value in updates.items():
            if not isinstance(value, Unset):
                setattr(token_db, field, value)
        token_hash = None
        if not isinstance(token_value, Unset):
            token_hash = self._hash_token(token_value)
            token_db.token_hash = token_hash
        async with handle_token_integrity(token_hash=token_hash):
            await self.session.commit()
        await self.session.refresh(token_db)
        logger.info(f"Token updated: {token_id}")
        return token_db
