from .rbac_errors import RBACConflictError, RBACNotFoundError, RBACUnexpectedError, RBACValidationError


class UserError(Exception):
    pass


class UserUsernameInvalidError(UserError, RBACValidationError):
    def __init__(self, username: str, pattern: str) -> None:
        self.username = username
        self.pattern = pattern
        super().__init__(
            code="USER_USERNAME_INVALID",
            message=f"User username '{username}' is invalid. Username should match pattern: '{pattern}'",
            details={"username": username, "pattern": pattern},
        )


class UserNotFoundError(UserError, RBACNotFoundError):
    def __init__(self, user_id: int) -> None:
        self.user_id = user_id
        super().__init__(
            code="USER_NOT_FOUND",
            message=f"User {user_id} not found",
            details={"user_id": user_id},
        )


class UserUsernameAlreadyExistError(UserError, RBACConflictError):
    def __init__(self, username: str) -> None:
        self.username = username
        super().__init__(
            code="USER_USERNAME_ALREADY_EXISTS",
            message=f"User with username '{username}' already exists",
            details={"username": username},
        )


class UserRolesUpdateIntersectingDeltaError(UserError, RBACValidationError):
    def __init__(self, role_id: int, delta_1: tuple[str, int], delta_2: tuple[str, int]) -> None:
        super().__init__(
            code="USER_ROLE_UPDATE_INTERSECTING_DELTA",
            message=f"Delta '{delta_1[0]}.{delta_1[1]}' operates on role {role_id}, but "
                    f"'{delta_2[0]}.{delta_2[1]}' operating on it too",
            details={
                "role_id": role_id,
                "delta_1": delta_1,
                "delta_2": delta_2,
            },
        )


class UserPermissionsUpdateIntersectingDeltaError(UserError, RBACValidationError):
    def __init__(self, permission_id: int, delta_1: tuple[str, int], delta_2: tuple[str, int]) -> None:
        super().__init__(
            code="USER_PERMISSION_UPDATE_INTERSECTING_DELTA",
            message=f"Delta '{delta_1[0]}.{delta_1[1]}' operates on permission {permission_id}, but "
                    f"'{delta_2[0]}.{delta_2[1]}' operating on it too",
            details={
                "permission_id": permission_id,
                "delta_1": delta_1,
                "delta_2": delta_2,
            },
        )


class UserUsernameNullError(UserError, RBACValidationError):
    def __init__(self) -> None:
        super().__init__(
            code="USER_USERNAME_NOT_NULLABLE",
            message="User username is not nullable",
        )


class UserPasswordNullError(UserError, RBACUnexpectedError):
    def __init__(self) -> None:
        super().__init__(
            code="USER_PASSWORD_HASH_NOT_NULLABLE",
            message="User password_hash is not nullable",
        )
