from collections.abc import Sequence
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from rbac.constants import RBACConstants
from rbac.enums import PolicyEffectEnum


class UserBase(BaseModel):
    username: str = Field(
        max_length=RBACConstants.USER_USERNAME_MAX_LEN,
        pattern=RBACConstants.USER_USERNAME_PATTERN,
    )


class UserCreate(UserBase):
    password: str = Field(
        min_length=RBACConstants.USER_PASSWORD_MIN_LEN,
        max_length=RBACConstants.USER_PASSWORD_MAX_LEN,
    )


class UserUpdate(BaseModel):
    username: str | None = Field(
        default=None,
        pattern=RBACConstants.USER_USERNAME_PATTERN,
        max_length=RBACConstants.USER_USERNAME_MAX_LEN,
    )
    password: str | None = Field(
        default=None,
        min_length=RBACConstants.USER_PASSWORD_MIN_LEN,
        max_length=RBACConstants.USER_PASSWORD_MAX_LEN,
    )


class UserRead(UserBase):
    id: int
    created_at: datetime
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class UsersRead(BaseModel):
    users: Sequence[UserRead]


class UserRoleBase(BaseModel):
    role_id: int
    effect: PolicyEffectEnum

    model_config = ConfigDict(from_attributes=True)


class UserRoles(BaseModel):
    user_id: int
    roles: Sequence[UserRoleBase]


class UserRoleUpdate(UserRoleBase):
    pass


class UserRolesUpdate(BaseModel):
    set: list[UserRoleUpdate] = Field(default_factory=list[UserRoleUpdate])
    remove: list[int] = Field(default_factory=list[int])


class UserPermissionBase(BaseModel):
    permission_id: int
    effect: PolicyEffectEnum

    model_config = ConfigDict(from_attributes=True)


class UserPermissions(BaseModel):
    user_id: int
    permissions: Sequence[UserPermissionBase]


class UserPermissionUpdate(UserPermissionBase):
    pass


class UserPermissionsUpdate(BaseModel):
    set: list[UserPermissionUpdate] = Field(default_factory=list[UserPermissionUpdate])
    remove: list[int] = Field(default_factory=list[int])
