from dishka import AsyncContainer, make_async_container

from rbac.configs import RBACConfig

from .kdb_provider import KDBProvider
from .pg_config_provider import PGConfigProvider
from .sqlalchemy_provider import SqlalchemyProvider


def make_rbac_container(rbac_config_instance: RBACConfig) -> AsyncContainer:
    return make_async_container(
        KDBProvider(),
        PGConfigProvider(),
        SqlalchemyProvider(),
        context={RBACConfig: rbac_config_instance},
    )
