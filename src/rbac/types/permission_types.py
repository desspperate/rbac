from typing import TypedDict


class PermissionPatch(TypedDict, total=False):
    codename: str
    description: str | None
