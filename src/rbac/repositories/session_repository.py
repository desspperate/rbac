from sqlalchemy import insert, update
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.enums import ForcedSessionStatusEnum
from rbac.models import Session
from rbac.types import SessionPatch
from rbac.utils import BaseRepository


class SessionRepository(BaseRepository[Session]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Session)

    async def create_session(
            self,
            user_id: int,
            forced_status: ForcedSessionStatusEnum | None,
            user_agent: str,
            ip_address: str,
    ) -> Session:
        statement = (
            insert(Session)
            .values(
                user_id=user_id,
                forced_status=forced_status,
                user_agent=user_agent,
                ip_address=ip_address,
            )
            .returning(Session)
        )
        result = await self.session.execute(statement)
        return result.scalar_one()

    async def update_session(
            self,
            session_id: int,
            session_patch: SessionPatch,
    ) -> Session:
        statement = (
            update(Session)
            .where(Session.id == session_id)
            .values(**session_patch)
            .returning(Session)
        )
        result = await self.session.execute(statement)
        return result.scalar_one()
