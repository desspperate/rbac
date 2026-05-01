from rbac.enums import TokenTypeEnum

from .rbac_errors import RBACUnauthorizedError


class InvalidCredentialsError(RBACUnauthorizedError):
    def __init__(self) -> None:
        super().__init__(
            code="INVALID_CREDENTIALS",
            message="Incorrect username or password",
        )


class TokenRevokedError(RBACUnauthorizedError):
    def __init__(self, token_type: TokenTypeEnum) -> None:
        super().__init__(
            code="TOKEN_REVOKED",
            message=f"{token_type.value.capitalize()} token has been revoked",
        )


class TokenExpiredError(RBACUnauthorizedError):
    def __init__(self, token_type: TokenTypeEnum) -> None:
        super().__init__(
            code="TOKEN_EXPIRED",
            message=f"{token_type.value.capitalize()} token has expired",
        )


class TokenSessionMismatchError(RBACUnauthorizedError):
    def __init__(self) -> None:
        super().__init__(
            code="TOKEN_SESSION_MISMATCH",
            message="Tokens are not from the same session",
        )


class TokenTypeMismatchError(RBACUnauthorizedError):
    def __init__(self, token_type: TokenTypeEnum) -> None:
        super().__init__(
            code="TOKEN_TYPE_MISMATCH",
            message=f"Token is not {token_type.value.lower()}",
        )


class TokenInvalidError(RBACUnauthorizedError):
    def __init__(self, token_type: TokenTypeEnum | None = None) -> None:
        super().__init__(
            code="TOKEN_INVALID",
            message=f"{"" if token_type is None else token_type.value.capitalize() + " "}"
                    f"{"Token" if token_type is None else "token"} "
                    f"is invalid",
        )


class SessionRevokedError(RBACUnauthorizedError):
    def __init__(self) -> None:
        super().__init__(
            code="SESSION_REVOKED",
            message="Session has been revoked",
        )
