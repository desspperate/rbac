from typing import Any


class RBACError(Exception):
    def __init__(
            self,
            code: str,
            message: str,
            details: dict[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.details = details
        super().__init__(message)


class RBACUnexpectedError(RBACError):
    code: str = "UNEXPECTED_ERROR"
    message: str = "Unexpected internal error"

    def __init__(
            self,
            code: str = "UNEXPECTED_ERROR",
            message: str = "Unexpected internal error",
    ) -> None:
        self.code = code
        self.message = message
        super().__init__(
            code=code,
            message=message,
        )


class RBACConflictError(RBACError):
    pass


class RBACNotFoundError(RBACError):
    pass


class RBACValidationError(RBACError):
    pass


class RBACUnauthorizedError(RBACError):
    pass


class RBACForbiddenError(RBACError):
    pass


class RBACBusinessLogicError(RBACError):
    pass


class RBACExternalServiceError(RBACError):
    pass
