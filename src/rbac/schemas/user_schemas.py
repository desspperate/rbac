from collections.abc import Sequence
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from rbac.constants import RBACConstants
from rbac.enums import PolicyEffectEnum


class UserBase(BaseModel):
    username: str = Field(
        max_length=RBACConstants.USER_USERNAME_MAX_LEN,
        pattern=RBACConstants.USER_USERNAME_PATTERN,
    )


class UserCreate(UserBase):
    password: SecretStr = Field(
        min_length=RBACConstants.USER_PASSWORD_MIN_LEN,
        max_length=RBACConstants.USER_PASSWORD_MAX_LEN,
    )


class UserUpdate(BaseModel):
    username: Annotated[str, Field(
        default=None,
        pattern=RBACConstants.USER_USERNAME_PATTERN,
        max_length=RBACConstants.USER_USERNAME_MAX_LEN,
    )]
    password: Annotated[SecretStr, Field(
        default=None,
        min_length=RBACConstants.USER_PASSWORD_MIN_LEN,
        max_length=RBACConstants.USER_PASSWORD_MAX_LEN,
    )]


class UserRead(UserBase):
    password_hash: str
    id: int
    created_at: datetime
    updated_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class UsersRead(BaseModel):
    users: Sequence[UserRead]
    page: int
    page_size: int
    total: int


class UserRoleBase(BaseModel):
    role_id: int
    effect: PolicyEffectEnum

    model_config = ConfigDict(from_attributes=True)


class UserRoles(BaseModel):
    user_id: int
    roles: Sequence[UserRoleBase]
    page: int | None = None
    page_size: int | None = None
    total: int | None = None


class UserRoleUpdate(UserRoleBase):
    pass


class UserRolesUpdate(BaseModel):
    set: Sequence[UserRoleUpdate] = Field(default_factory=Sequence[UserRoleUpdate])
    remove: Sequence[int] = Field(default_factory=Sequence[int])


class UserPermissionBase(BaseModel):
    permission_id: int
    effect: PolicyEffectEnum

    model_config = ConfigDict(from_attributes=True)


class UserPermissions(BaseModel):
    user_id: int
    permissions: Sequence[UserPermissionBase]
    page: int | None = None
    page_size: int | None = None
    total: int | None = None


class UserPermissionUpdate(UserPermissionBase):
    pass


class UserPermissionsUpdate(BaseModel):
    set: Sequence[UserPermissionUpdate] = Field(default_factory=Sequence[UserPermissionUpdate])
    remove: Sequence[int] = Field(default_factory=Sequence[int])
