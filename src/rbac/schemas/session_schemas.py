from collections.abc import Sequence
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from rbac.enums import ForcedSessionStatusEnum


class SessionBase(BaseModel):
    user_id: int
    forced_status: ForcedSessionStatusEnum | None = None
    user_agent: str
    ip_address: str


class SessionCreate(SessionBase):
    pass


class SessionUpdate(BaseModel):
    user_id: Annotated[int, Field(default=None)]
    forced_status: Annotated[ForcedSessionStatusEnum | None, Field(default=None)]
    user_agent: Annotated[str, Field(default=None)]
    ip_address: Annotated[str, Field(default=None)]


class SessionRead(SessionBase):
    id: int
    created_at: datetime
    updated_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class SessionsRead(BaseModel):
    sessions: Sequence[SessionRead]
    page: int
    page_size: int
    total: int

