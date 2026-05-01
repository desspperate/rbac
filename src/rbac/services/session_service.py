from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager

from asyncpg import ForeignKeyViolationError, NotNullViolationError
from loguru import logger
from sqlalchemy.exc import IntegrityError

from rbac.enums import ForcedSessionStatusEnum
from rbac.errors import (
    SessionIpAddressNullError,
    SessionNotFoundByIDError,
    SessionStillReferencedError,
    SessionUserAgentNullError,
    SessionUserIdNullError,
    UnhandledIntegrityError,
    UserNotFoundByIDError,
)
from rbac.models import Session, Token
from rbac.repositories import SessionRepository
from rbac.types import SessionPatch
from rbac.utils import HandleIntegrityHelpers, get_asyncpg_error


@asynccontextmanager
async def handle_session_integrity() -> AsyncIterator[None]:
    try:
        yield
    except IntegrityError as e:
        asyncpg_error = get_asyncpg_error(e)
        if asyncpg_error is None:
            raise UnhandledIntegrityError from e

        if isinstance(asyncpg_error, ForeignKeyViolationError):
            constraint = HandleIntegrityHelpers.get_constraint(asyncpg_error, e)
            _, failed_value, referrer_table = HandleIntegrityHelpers.get_details(asyncpg_error, e)

            if constraint == Session.FK_SESSION_USER_ID:
                raise UserNotFoundByIDError(user_id=failed_value) from e
            if constraint == Token.FK_TOKEN_SESSION_ID:
                raise SessionStillReferencedError(
                    session_id=failed_value,
                    related_object_type=referrer_table,
                ) from e
        elif isinstance(asyncpg_error, NotNullViolationError):
            column = HandleIntegrityHelpers.get_column(asyncpg_error, e)

            error_map = {
                "user_id": SessionUserIdNullError,
                "user_agent": SessionUserAgentNullError,
                "ip_address": SessionIpAddressNullError,
            }
            error = error_map.get(column)
            if error is not None:
                raise error from e

        raise UnhandledIntegrityError from e


class SessionService:
    def __init__(self, session_repository: SessionRepository) -> None:
        self.session_repository = session_repository

    async def get_session(self, session_id: int) -> Session:
        logger.info(f"Getting session: {session_id}")
        if (session := await self.session_repository.get_by_id(session_id)) is None:
            raise SessionNotFoundByIDError(session_id=session_id)
        return session

    async def get_sessions(self, page: int, size: int) -> tuple[Sequence[Session], int]:
        logger.info(f"Getting sessions for page: {page}, size: {size}")
        return await self.session_repository.list_all(skip=(page - 1) * size, limit=size)

    async def create_session(
            self,
            user_id: int,
            forced_status: ForcedSessionStatusEnum | None,
            user_agent: str,
            ip_address: str,
    ) -> Session:
        logger.info(f"Creating session for user: {user_id}")
        async with handle_session_integrity():
            return await self.session_repository.create_session(
                user_id=user_id,
                forced_status=forced_status,
                user_agent=user_agent,
                ip_address=ip_address,
            )

    async def delete_session(self, session_id: int) -> None:
        logger.info(f"Deleting session: {session_id}")
        async with handle_session_integrity():
            deleted = await self.session_repository.delete_by_id(session_id)
        if not deleted:
            raise SessionNotFoundByIDError(session_id=session_id)

    async def update_session(self, session_id: int, session_patch: SessionPatch) -> Session:
        logger.info(f"Updating session: {session_id}")
        async with handle_session_integrity():
            return await self.session_repository.update_session(
                session_id=session_id,
                session_patch=session_patch,
            )
