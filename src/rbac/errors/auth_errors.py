from .rbac_errors import RBACUnauthorizedError


class InvalidCredentialsError(RBACUnauthorizedError):
    def __init__(self) -> None:
        super().__init__(
            code="INVALID_CREDENTIALS",
            message="Incorrect username or password",
        )


class TokenRevokedError(RBACUnauthorizedError):
    def __init__(self) -> None:
        super().__init__(
            code="TOKEN_REVOKED",
            message="Token has been revoked",
        )


class TokenExpiredError(RBACUnauthorizedError):
    def __init__(self) -> None:
        super().__init__(
            code="TOKEN_EXPIRED",
            message="Token has expired",
        )


class TokenMismatchError(RBACUnauthorizedError):
    def __init__(self) -> None:
        super().__init__(
            code="TOKEN_MISMATCH",
            message="Token is invalid",
        )
