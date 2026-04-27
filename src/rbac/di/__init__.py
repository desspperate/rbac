from dishka import AsyncContainer, make_async_container

from rbac.configs import RBACConfig

from .kdb_provider import KDBProvider
from .permission_provider import PermissionProvider
from .pg_config_provider import PGConfigProvider
from .role_provider import RoleProvider
from .sqlalchemy_provider import SqlalchemyProvider
from .token_provider import TokenProvider
from .user_provider import UserProvider


def make_rbac_container(rbac_config_instance: RBACConfig) -> AsyncContainer:
    return make_async_container(
        KDBProvider(),
        PGConfigProvider(),
        SqlalchemyProvider(),
        RoleProvider(),
        UserProvider(),
        PermissionProvider(),
        TokenProvider(),
        context={RBACConfig: rbac_config_instance},
    )
