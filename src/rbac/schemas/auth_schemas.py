from pydantic import BaseModel, Field, SecretStr

from rbac.constants import RBACConstants


class LoginRequest(BaseModel):
    username: str = Field(
        max_length=RBACConstants.USER_USERNAME_MAX_LEN,
        pattern=RBACConstants.USER_USERNAME_PATTERN,
    )
    password: SecretStr = Field(
        min_length=RBACConstants.USER_PASSWORD_MIN_LEN,
        max_length=RBACConstants.USER_PASSWORD_MAX_LEN,
    )


class RegisterRequest(LoginRequest):
    pass


class RefreshRequest(BaseModel):
    access_token: SecretStr
    refresh_token: SecretStr


class TokenPair(BaseModel):
    access_token: str
    expires_in: int
    refresh_token: str
    refresh_expires_in: int
    token_type: str = "Bearer"  #  noqa: S105
