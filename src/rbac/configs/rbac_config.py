from pydantic_settings import BaseSettings


class RBACConfig(BaseSettings):
    FASTAPI_TITLE: str
    DEBUG: bool
    LOGURU_LEVEL: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_MINUTES: int
