from typing import Any

from rbac.enums import TokenTypeEnum
from rbac.errors.rbac_errors import RBACConflictError, RBACNotFoundError, RBACValidationError


class TokenNotFoundError(RBACNotFoundError):
    def __init__(
            self,
            message: str = "Token not found",
            details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            code="TOKEN_NOT_FOUND",
            message=message,
            details=details,
        )


class TokenNotFoundByIDError(TokenNotFoundError):
    def __init__(self, token_id: int) -> None:
        self.token_id = token_id
        super().__init__(
            message=f"Token {token_id} not found",
            details={"token_id": token_id},
        )


class TokenNotFoundByTokenHashError(TokenNotFoundError):
    def __init__(self, token_hash: str) -> None:
        self.token_hash = token_hash
        super().__init__(
            message=f"Token with token_hash: '{token_hash}' not found",
            details={"token_hash": token_hash},
        )


class TokenTokenHashAlreadyExistError(RBACConflictError):
    def __init__(self, token_hash: str) -> None:
        self.token_hash = token_hash
        super().__init__(
            code="TOKEN_TOKEN_HASH_ALREADY_EXIST",
            message=f"token_hash: '{token_hash}' already taken",
            details={"token_hash": token_hash},
        )


class TokenSessionIdNullError(RBACValidationError):
    def __init__(self) -> None:
        super().__init__(
            code="TOKEN_SESSION_ID_NULL",
            message="Token session_id is not nullable",
        )


class TokenTokenHashNullError(RBACValidationError):
    def __init__(self) -> None:
        super().__init__(
            code="TOKEN_TOKEN_HASH_NULL",
            message="Token token_hash is not nullable",
        )


class TokenTokenTypeNullError(RBACValidationError):
    def __init__(self) -> None:
        super().__init__(
            code="TOKEN_TOKEN_TYPE_NULL",
            message="Token token_type is not nullable",
        )


class TokenExpiresAtNullError(RBACValidationError):
    def __init__(self) -> None:
        super().__init__(
            code="TOKEN_EXPIRES_AT_NULL",
            message="Token expires_at is not nullable",
        )


class UnsupportedTokenTypeError(RBACValidationError):
    def __init__(self, token_type: TokenTypeEnum) -> None:
        super().__init__(
            code="UNSUPPORTED_TOKEN_TYPE",
            message=f"Token of type: {token_type.name} is not supported",
            details={"token_type": token_type.name},
        )


class ActiveTokenAlreadyExistsError(RBACConflictError):
    def __init__(self, session_id: int, token_type: TokenTypeEnum) -> None:
        self.session_id = session_id
        self.token_type = token_type
        super().__init__(
            code="ACTIVE_TOKEN_ALREADY_EXISTS",
            message="An active token of this type already exists for the session",
            details={"session_id": session_id, "token_type": token_type.name},
        )
