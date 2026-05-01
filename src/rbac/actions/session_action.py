from collections.abc import Sequence

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.enums import ForcedSessionStatusEnum
from rbac.models import Session
from rbac.services import SessionService
from rbac.types import SessionPatch


class SessionAction:
    def __init__(
            self,
            session: AsyncSession,
            session_service: SessionService,
    ) -> None:
        self.session = session
        self.session_service = session_service

    async def get_session(self, session_id: int) -> Session:
        result = await self.session_service.get_session(session_id=session_id)
        logger.info(f"Found session: {session_id}")
        return result

    async def get_sessions(self, page: int, size: int) -> tuple[Sequence[Session], int]:
        result = await self.session_service.get_sessions(page=page, size=size)
        logger.info(f"Found {len(result[0])} sessions")
        return result

    async def create_session(
            self,
            user_id: int,
            forced_status: ForcedSessionStatusEnum | None,
            user_agent: str,
            ip_address: str,
    ) -> Session:
        session = await self.session_service.create_session(
            user_id=user_id,
            forced_status=forced_status,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        await self.session.commit()
        logger.info(f"Created session id={session.id} for user '{session.user_id}'")
        return session

    async def delete_session(self, session_id: int) -> None:
        await self.session_service.delete_session(session_id=session_id)
        await self.session.commit()
        logger.info(f"Session deleted: {session_id}")

    async def update_session(self, session_id: int, session_patch: SessionPatch) -> Session:
        session = await self.session_service.update_session(
            session_id=session_id,
            session_patch=session_patch,
        )
        await self.session.commit()
        logger.info(f"Updated session: {session_id}")
        return session
