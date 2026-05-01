from collections.abc import Sequence
from typing import TypedDict

from rbac.enums import AccessTokenStatusEnum, TokenPairStatusEnum


class TokenPairType(TypedDict):
    access_token: str
    expires_in: int
    refresh_token: str
    refresh_expires_in: int
    token_type: str


class UserIdentityType(TypedDict):
    status: AccessTokenStatusEnum
    user_id: str
    username: str
    roles: Sequence[str]
    permissions: Sequence[str]


class LogoutResultType(TypedDict):
    status: AccessTokenStatusEnum
    session_id: str


class LogoutAllResultType(TypedDict):
    status: AccessTokenStatusEnum
    user_id: str
    current_session_id: str


class RefreshResultType(TypedDict):
    status: TokenPairStatusEnum
    user_id: str
    session_id: str
