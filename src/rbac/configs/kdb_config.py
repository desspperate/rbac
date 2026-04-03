from pydantic import SecretStr
from pydantic_settings import BaseSettings


class KDBConfig(BaseSettings):
    KDB_PASSWORD: SecretStr
    KDB_HOST: str
    KDB_PORT: int
    KDB_DB: int
