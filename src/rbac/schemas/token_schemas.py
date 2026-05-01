from collections.abc import Sequence
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, SecretBytes

from rbac.constants import RBACConstants
from rbac.enums import ForcedTokenStatusEnum, TokenTypeEnum


class TokenBase(BaseModel):
    session_id: int
    token_type: TokenTypeEnum
    forced_status: ForcedTokenStatusEnum | None = None


class TokenCreate(TokenBase):
    token_value: SecretBytes | None = None
    expires_at: datetime | None = None


class TokenUpdate(BaseModel):
    session_id: Annotated[int, Field(default=None)]
    token_type: Annotated[TokenTypeEnum, Field(default=None)]
    forced_status: Annotated[ForcedTokenStatusEnum | None, Field(default=None)]
    token_value: Annotated[SecretBytes, Field(default=None)]
    expires_at: Annotated[datetime, Field(default=None)]


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
    page: int
    page_size: int
    total: int
