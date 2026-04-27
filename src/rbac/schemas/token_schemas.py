from collections.abc import Sequence
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from rbac.constants import RBACConstants
from rbac.enums import ForcedTokenStatusEnum, TokenTypeEnum


class TokenBase(BaseModel):
    user_id: int
    token_type: TokenTypeEnum
    forced_status: ForcedTokenStatusEnum | None = None


class TokenCreate(TokenBase):
    token_value: bytes | None = None
    expires_at: datetime | None = None


class TokenUpdate(BaseModel):
    user_id: int | None = None
    token_type: TokenTypeEnum | None = None
    forced_status: ForcedTokenStatusEnum | None = None
    token_value: bytes | None = None
    expires_at: datetime | None = None


class TokenRead(TokenBase):
    expires_at: datetime
    token_hash: str = Field(max_length=RBACConstants.HASH_MAX_LEN)
    id: int
    created_at: datetime
    updated_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class TokenPrivateRead(TokenRead):
    token: str = Field(max_length=RBACConstants.TOKEN_LENGTH)


class TokensRead(BaseModel):
    tokens: Sequence[TokenRead]
