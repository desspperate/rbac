import os
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

from asyncpg import ForeignKeyViolationError, NotNullViolationError, UniqueViolationError
from loguru import logger
from pydantic import SecretBytes
from sqlalchemy.exc import IntegrityError

from rbac.configs import RBACConfig
from rbac.enums import ForcedTokenStatusEnum, TokenTypeEnum
from rbac.errors import (
    ActiveTokenAlreadyExistsError,
    SessionNotFoundByIDError,
    TokenExpiresAtNullError,
    TokenNotFoundByIDError,
    TokenNotFoundByTokenHashError,
    TokenSessionIdNullError,
    TokenTokenHashAlreadyExistError,
    TokenTokenHashNullError,
    TokenTokenTypeNullError,
    UnhandledIntegrityError,
    UnsupportedTokenTypeError,
)
from rbac.models import Token
from rbac.repositories import TokenRepository
from rbac.schemas import TokenPrivateRead
from rbac.types import TokenPatch
from rbac.utils import HandleIntegrityHelpers, get_asyncpg_error, hash_token


@asynccontextmanager
async def handle_token_integrity(
        token_hash: str | None,
        session_id: int | None = None,
        token_type: TokenTypeEnum | None = None,
) -> AsyncIterator[None]:
    try:
        yield
    except IntegrityError as e:
        asyncpg_error = get_asyncpg_error(e)
        if asyncpg_error is None:
            raise UnhandledIntegrityError from e

        if isinstance(asyncpg_error, UniqueViolationError | ForeignKeyViolationError):
            constraint = HandleIntegrityHelpers.get_constraint(asyncpg_error, e)

            if isinstance(asyncpg_error, UniqueViolationError):
                if constraint == Token.UQ_TOKEN_TOKEN_HASH and isinstance(token_hash, str):
                    raise TokenTokenHashAlreadyExistError(token_hash=token_hash) from e

                if (
                    constraint == Token.UQ_TOKEN_ACTIVE_PER_SESSION_TYPE
                    and session_id is not None
                    and token_type is not None
                ):
                    raise ActiveTokenAlreadyExistsError(
                        session_id=session_id,
                        token_type=token_type,
                    ) from e

            if isinstance(asyncpg_error, ForeignKeyViolationError):
                _, failed_value, _ = HandleIntegrityHelpers.get_details(asyncpg_error, e)

                if constraint == Token.FK_TOKEN_SESSION_ID:
                    raise SessionNotFoundByIDError(session_id=failed_value) from e
        elif isinstance(asyncpg_error, NotNullViolationError):
            column = HandleIntegrityHelpers.get_column(asyncpg_error, e)

            error_map = {
                "session_id": TokenSessionIdNullError,
                "token_hash": TokenTokenHashNullError,
                "token_type": TokenTokenTypeNullError,
                "expires_at": TokenExpiresAtNullError,
            }
            error = error_map.get(column)
            if error is not None:
                raise error from e

        raise UnhandledIntegrityError from e


class TokenService:
    def __init__(self, token_repository: TokenRepository, rbac_config: RBACConfig) -> None:
        self.token_repository = token_repository
        self.rbac_config = rbac_config

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
            raise TokenNotFoundByIDError(token_id)
        return token

    async def get_tokens(self, page: int, size: int) -> tuple[Sequence[Token], int]:
        logger.info(f"Getting tokens for page: {page}, size: {size}")
        return await self.token_repository.list_all(skip=(page - 1) * size, limit=size)

    async def create_token(
            self,
            session_id: int,
            token_type: TokenTypeEnum,
            provided_token: SecretBytes | None = None,
            forced_status: ForcedTokenStatusEnum | None = None,
            expires_at_: datetime | None = None,
    ) -> TokenPrivateRead:
        logger.info(f"Creating token '{token_type.name}' for session '{session_id}'")
        token_value: bytes = os.urandom(32) if provided_token is None else provided_token.get_secret_value()
        token_hash = hash_token(token_value)
        token_ttl = self.get_token_ttl(token_type=token_type)

        async with handle_token_integrity(
            token_hash=token_hash,
            session_id=session_id,
            token_type=token_type,
        ):
            token_db = await self.token_repository.create_token(
                session_id=session_id,
                token_hash=token_hash,
                token_type=token_type,
                forced_status=forced_status,
                expires_at=(
                    expires_at_ if expires_at_ is not None
                    else datetime.now(tz=UTC) + timedelta(minutes=token_ttl)
                ),
            )
        return TokenPrivateRead(
            session_id=token_db.session_id,
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
            raise TokenNotFoundByIDError(token_id=token_id)

    async def update_token(
            self,
            token_id: int,
            token_patch: TokenPatch,
    ) -> Token:
        logger.info(f"Updating token: {token_id}")

        token_value = token_patch.pop("token_value", None)
        if isinstance(token_value, SecretBytes):
            token_patch["token_hash"] = hash_token(token_value.get_secret_value())

        async with handle_token_integrity(token_hash=token_patch.get("token_hash")):
            return await self.token_repository.update_token(token_id=token_id, token_patch=token_patch)

    async def find_by_token_hash(self, token_hash: str) -> Token:
        logger.info(f"Finding token by token hash: {token_hash}")
        if (token := await self.token_repository.get_by_token_hash(token_hash=token_hash)) is None:
            raise TokenNotFoundByTokenHashError(token_hash=token_hash)
        return token

    async def find_by_token_hash_for_update(self, token_hash: str) -> Token:
        logger.info(f"Finding token by token hash (for update): {token_hash}")
        if (token := await self.token_repository.get_by_token_hash_for_update(token_hash=token_hash)) is None:
            raise TokenNotFoundByTokenHashError(token_hash=token_hash)
        return token
