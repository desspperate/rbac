from typing import TypedDict

from rbac.enums import ForcedSessionStatusEnum


class SessionPatch(TypedDict, total=False):
    user_id: int
    forced_status: ForcedSessionStatusEnum | None
    user_agent: str
    ip_address: str
