from collections.abc import Sequence

from .rbac_errors import (
    RBACConflictError,
    RBACNotFoundError,
    RBACValidationError,
)


class RoleError(Exception):
    pass


class RoleNotFoundError(RoleError, RBACNotFoundError):
    def __init__(self, role_id: int) -> None:
        self.role_id = role_id
        super().__init__(
            code="ROLE_NOT_FOUND",
            message=f"Role {role_id} not found",
            details={"role_id": role_id},
        )


class RoleNameAlreadyExistError(RoleError, RBACConflictError):
    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(
            code="ROLE_ALREADY_EXIST",
            message=f"Role '{name}' already exist",
            details={"name": name},
        )


class RolesNotFoundError(RoleError, RBACNotFoundError):
    def __init__(self, role_ids: Sequence[int]) -> None:
        self.role_ids = role_ids
        super().__init__(
            code="ROLES_NOT_FOUND",
            message=f"Roles {role_ids[:10]} not found",
            details={"role_ids": role_ids},
        )


class RoleNameNullError(RoleError, RBACValidationError):
    def __init__(self) -> None:
        super().__init__(
            code="ROLE_NAME_NOT_NULLABLE",
            message="Role name is not nullable",
        )


class RolePermissionsUpdateIntersectingDeltaError(RoleError, RBACValidationError):
    def __init__(self, permission_id: int, delta_1: tuple[str, int], delta_2: tuple[str, int]) -> None:
        super().__init__(
            code="ROLE_PERMISSION_UPDATE_INTERSECTING_DELTA",
            message=f"Delta '{delta_1[0]}.{delta_1[1]}' operates on permission {permission_id}, but "
                    f"'{delta_2[0]}.{delta_2[1]}' operating on it too",
            details={
                "permission_id": permission_id,
                "delta_1": delta_1,
                "delta_2": delta_2,
            },
        )


class RoleNameInvalidError(RoleError, RBACValidationError):
    def __init__(self, name: str, pattern: str) -> None:
        self.name = name
        self.pattern = pattern
        super().__init__(
            code="ROLE_NAME_INVALID",
            message=f"Role name '{name}' is invalid. Name should match pattern '{pattern}'",
            details={"name": name, "pattern": pattern},
        )


class RoleDescriptionInvalidError(RoleError, RBACValidationError):
    def __init__(self, description: str, pattern: str) -> None:
        self.description = description
        self.pattern = pattern
        super().__init__(
            code="ROLE_DESCRIPTION_INVALID",
            message=f"Role description '{description}' is invalid. Description should match pattern '{pattern}'",
            details={"description": description, "pattern":pattern},
        )
