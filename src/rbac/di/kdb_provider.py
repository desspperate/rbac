from dishka import Provider, Scope, provide

from rbac.configs import KDBConfig


class KDBProvider(Provider):
    @provide(scope=Scope.APP)
    def get_kdb_config(self) -> KDBConfig:
        return KDBConfig()  # type: ignore[call-args]
