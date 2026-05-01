from datetime import datetime
from typing import TypedDict

from pydantic import SecretBytes

from rbac.enums import ForcedTokenStatusEnum, TokenTypeEnum


class TokenPatch(TypedDict, total=False):
    session_id: int
    token_type: TokenTypeEnum
    expires_at: datetime
    token_value: SecretBytes
    token_hash: str
    forced_status: ForcedTokenStatusEnum | None
