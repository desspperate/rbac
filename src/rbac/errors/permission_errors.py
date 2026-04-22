from collections.abc import Sequence

from .rbac_errors import RBACConflictError, RBACNotFoundError, RBACValidationError


class BasePermissionError(Exception):
    pass


class PermissionNotFoundError(BasePermissionError, RBACNotFoundError):
    def __init__(self, permission_id: int) -> None:
        self.permission_id = permission_id
        super().__init__(
            code="PERMISSION_NOT_FOUND",
            message=f"Permission {permission_id} not found",
            details={"permission_id": permission_id},
        )


class PermissionsNotFoundError(BasePermissionError, RBACNotFoundError):
    def __init__(self, permission_ids: Sequence[int]) -> None:
        self.permission_ids = permission_ids
        super().__init__(
            code="PERMISSIONS_NOT_FOUND",
            message=f"Permissions {permission_ids[:10]} not found",
            details={"permission_ids": permission_ids},
        )


class PermissionCodenameConflictError(BasePermissionError, RBACConflictError):
    def __init__(self, codename: str) -> None:
        self.codename = codename
        super().__init__(
            code="PERMISSION_ALREADY_EXIST",
            message=f"Permission '{codename}' already exist",
            details={"codename": codename},
        )


class PermissionCodenameInvalidError(BasePermissionError, RBACValidationError):
    def __init__(self, codename: str, pattern: str) -> None:
        self.codename = codename
        self.pattern = pattern
        super().__init__(
            code="PERMISSION_CODENAME_INVALID",
            message=f"Permission codename '{codename}' is invalid. Codename should match pattern: '{pattern}'",
            details={"codename": codename, "pattern": pattern},
        )


class PermissionCodenameNotNullError(BasePermissionError, RBACValidationError):
    def __init__(self) -> None:
        super().__init__(
            code="PERMISSION_CODENAME_NOT_NULL",
            message="Permission codename not nullable",
        )


class PermissionDescriptionInvalidError(BasePermissionError, RBACValidationError):
    def __init__(self, description: str, pattern: str) -> None:
        self.description = description
        self.pattern = pattern
        super().__init__(
            code="PERMISSION_DESCRIPTION_INVALID",
            message=f"Permission description '{description}' is invalid. Description should match pattern: '{pattern}'",
            details={"description": description, "pattern": pattern},
        )
