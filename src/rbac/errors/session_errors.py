from typing import Any

from rbac.errors.rbac_errors import RBACConflictError, RBACNotFoundError, RBACValidationError


class SessionNotFoundError(RBACNotFoundError):
    def __init__(
            self,
            message: str = "Session not found",
            details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            code="SESSION_NOT_FOUND",
            message=message,
            details=details,
        )


class SessionNotFoundByIDError(SessionNotFoundError):
    def __init__(self, session_id: int | str) -> None:
        self.session_id = session_id
        super().__init__(
            message=f"Session {session_id} not found",
            details={"session_id": session_id},
        )


class SessionStillReferencedError(RBACConflictError):
    def __init__(self, session_id: int | str, related_object_type: str) -> None:
        self.session_id = session_id
        super().__init__(
            code="SESSION_STILL_REFERENCED",
            message=f"Session {session_id} is still referenced by {related_object_type}",
            details={"session_id": session_id, "related_object_type": related_object_type},
        )


class SessionUserIdNullError(RBACValidationError):
    def __init__(self) -> None:
        super().__init__(
            code="SESSION_USER_ID_NULL",
            message="Session user_id is not nullable",
        )


class SessionUserAgentNullError(RBACValidationError):
    def __init__(self) -> None:
        super().__init__(
            code="SESSION_USER_AGENT_NULL",
            message="Session user_agent is not nullable",
        )


class SessionIpAddressNullError(RBACValidationError):
    def __init__(self) -> None:
        super().__init__(
            code="SESSION_IP_ADDRESS_NULL",
            message="Session ip_address is not nullable",
        )
