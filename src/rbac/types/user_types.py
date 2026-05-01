from collections.abc import Sequence
from typing import TypedDict

from pydantic import SecretStr

from rbac.enums import PolicyEffectEnum


class UserPatch(TypedDict, total=False):
    username: str
    password: SecretStr
    password_hash: str


class UserPermissionType(TypedDict):
    user_id: int
    permission_id: int
    effect: PolicyEffectEnum


class UserPermissionsPatch(TypedDict):
    set: Sequence[UserPermissionType]
    remove: Sequence[int]


class UserRoleType(TypedDict):
    user_id: int
    role_id: int
    effect: PolicyEffectEnum


class UserRolesPatch(TypedDict):
    set: Sequence[UserRoleType]
    remove: Sequence[int]
