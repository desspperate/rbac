from collections.abc import Sequence
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from rbac.constants import RBACConstants


class PermissionBase(BaseModel):
    codename: str = Field(
        pattern=RBACConstants.PERMISSION_CODENAME_PATTERN,
        max_length=RBACConstants.PERMISSION_CODENAME_MAX_LEN,
    )
    description: str | None = Field(
        None,
        max_length=RBACConstants.PERMISSION_DESCRIPTION_MAX_LEN,
        pattern=RBACConstants.DESCRIPTION_PATTERN,
    )


class PermissionCreate(PermissionBase):
    pass


class PermissionUpdate(BaseModel):
    codename: str | None = Field(
        None,
        pattern=RBACConstants.PERMISSION_CODENAME_PATTERN,
        max_length=RBACConstants.PERMISSION_CODENAME_MAX_LEN,
    )
    description: str | None = Field(
        None,
        max_length=RBACConstants.PERMISSION_DESCRIPTION_MAX_LEN,
        pattern=RBACConstants.DESCRIPTION_PATTERN,
    )


class PermissionRead(PermissionBase):
    id: int
    created_at: datetime
    updated_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class PermissionsRead(BaseModel):
    permissions: Sequence[PermissionRead]
    page: int
    page_size: int
    total: int
