from collections.abc import Sequence
from typing import TypedDict

from rbac.enums import PolicyEffectEnum


class RolePatch(TypedDict, total=False):
    name: str
    description: str | None


class RolePermissionType(TypedDict):
    role_id: int
    permission_id: int
    effect: PolicyEffectEnum


class RolePermissionsPatch(TypedDict):
    set: Sequence[RolePermissionType]
    remove: Sequence[int]
