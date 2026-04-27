from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from rbac.enums import ForcedTokenStatusEnum, TokenTypeEnum
from rbac.models import Token
from rbac.utils import BaseRepository


class TokenRepository(BaseRepository[Token]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Token)

    async def create_token(
            self,
            user_id: int,
            token_hash: str,
            token_type: TokenTypeEnum,
            forced_status: ForcedTokenStatusEnum | None,
            expires_at: datetime,
    ) -> Token:
        new_token = Token(
            user_id=user_id,
            token_hash=token_hash,
            token_type=token_type,
            forced_status=forced_status,
            expires_at=expires_at,
        )
        self.session.add(new_token)
        await self.session.flush()
        await self.session.refresh(new_token)
        return new_token
