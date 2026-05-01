from collections.abc import Sequence
from datetime import datetime

from loguru import logger
from pydantic import SecretBytes
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.enums import ForcedTokenStatusEnum, TokenTypeEnum
from rbac.models import Token
from rbac.schemas import TokenPrivateRead
from rbac.services import TokenService
from rbac.types import TokenPatch


class TokenAction:
    def __init__(
            self,
            session: AsyncSession,
            token_service: TokenService,
    ) -> None:
        self.session = session
        self.token_service = token_service

    async def get_tokens(self, page: int, size: int) -> tuple[Sequence[Token], int]:
        result = await self.token_service.get_tokens(page=page, size=size)
        logger.info(f"Found {len(result[0])} tokens")
        return result

    async def get_token(self, token_id: int) -> Token:
        result = await self.token_service.get_token(token_id=token_id)
        logger.info(f"Found token: {token_id}")
        return result

    async def create_token(
            self,
            session_id: int,
            token_type: TokenTypeEnum,
            provided_token: SecretBytes | None,
            forced_status: ForcedTokenStatusEnum | None,
            expires_at: datetime | None,
    ) -> TokenPrivateRead:
        token = await self.token_service.create_token(
            session_id=session_id,
            token_type=token_type,
            provided_token=provided_token,
            forced_status=forced_status,
            expires_at_=expires_at,
        )
        await self.session.commit()
        logger.info(f"Created token id={token.id} token_type='{token.token_type.name}' for session "
                    f"'{token.session_id}'")
        return token

    async def delete_token(self, token_id: int) -> None:
        await self.token_service.delete_token(token_id=token_id)
        await self.session.commit()
        logger.info(f"Token deleted: {token_id}")

    async def update_token(self, token_id: int, token_patch: TokenPatch) -> Token:
        token = await self.token_service.update_token(token_id=token_id, token_patch=token_patch)
        await self.session.commit()
        logger.info(f"Updated token: {token_id}")
        return token
