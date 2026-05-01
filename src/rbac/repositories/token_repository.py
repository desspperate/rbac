from datetime import datetime

from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.enums import ForcedTokenStatusEnum, TokenTypeEnum
from rbac.models import Token
from rbac.types import TokenPatch
from rbac.utils import BaseRepository


class TokenRepository(BaseRepository[Token]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Token)

    async def create_token(
            self,
            session_id: int,
            token_hash: str,
            token_type: TokenTypeEnum,
            forced_status: ForcedTokenStatusEnum | None,
            expires_at: datetime,
    ) -> Token:
        statement = (
            insert(Token)
            .values(
                session_id=session_id,
                token_hash=token_hash,
                token_type=token_type,
                forced_status=forced_status,
                expires_at=expires_at,
            )
            .returning(Token)
        )
        result = await self.session.execute(statement)
        return result.scalar_one()

    async def update_token(self, token_id: int, token_patch: TokenPatch) -> Token:
        statement = (
            update(Token)
            .where(Token.id == token_id)
            .values(**token_patch)
            .returning(Token)
        )
        result = await self.session.execute(statement)
        return result.scalar_one()

    async def get_by_token_hash(self, token_hash: str) -> Token | None:
        statement = (
            select(Token)
            .where(Token.token_hash == token_hash)
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def get_by_token_hash_for_update(self, token_hash: str) -> Token | None:
        statement = (
            select(Token)
            .where(Token.token_hash == token_hash)
            .with_for_update()
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()
