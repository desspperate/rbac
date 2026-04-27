from collections.abc import Sequence
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from rbac.constants import RBACConstants
from rbac.enums import PolicyEffectEnum


class RoleBase(BaseModel):
    name: str = Field(
        pattern=RBACConstants.ROLE_NAME_PATTERN,
        max_length=RBACConstants.ROLE_NAME_MAX_LEN,
    )
    description: str | None = Field(
        default=None,
        max_length=RBACConstants.ROLE_DESCRIPTION_MAX_LEN,
        pattern=RBACConstants.DESCRIPTION_PATTERN,
    )


class RoleCreate(RoleBase):
    pass


class RoleUpdate(BaseModel):
    name: str | None = Field(
        default=None,
        pattern=RBACConstants.ROLE_NAME_PATTERN,
        max_length=RBACConstants.ROLE_NAME_MAX_LEN,
    )
    description: str | None = Field(
        default=None,
        max_length=RBACConstants.ROLE_DESCRIPTION_MAX_LEN,
        pattern=RBACConstants.DESCRIPTION_PATTERN,
    )

class RoleRead(RoleBase):
    id: int
    created_at: datetime
    updated_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class RolesRead(BaseModel):
    roles: Sequence[RoleRead]
    page: int
    page_size: int
    total: int


class RolePermissionBase(BaseModel):
    permission_id: int
    effect: PolicyEffectEnum

    model_config = ConfigDict(from_attributes=True)


class RolePermissions(BaseModel):
    role_id: int
    permissions: Sequence[RolePermissionBase]
    page: int | None = None
    page_size: int | None = None
    total: int | None = None


class RolePermissionUpdate(RolePermissionBase):
    pass


class RolePermissionsUpdate(BaseModel):
    set: list[RolePermissionUpdate] = Field(default_factory=list[RolePermissionUpdate])
    remove: list[int] = Field(default_factory=list[int])
