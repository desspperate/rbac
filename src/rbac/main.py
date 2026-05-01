import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from dishka.integrations import fastapi as fastapi_integration
from fastapi import FastAPI
from loguru import logger

from rbac.configs import KDBConfig, PGConfig, RBACConfig
from rbac.di import make_rbac_container
from rbac.error_handlers import register_error_handler
from rbac.routers import (
    auth_router,
    permission_router,
    ping_pong_router,
    role_router,
    session_router,
    token_router,
    user_router,
)
from rbac.utils import print_pd_settings


def create_app() -> FastAPI:
    logger.remove()
    logger.add(sys.stderr, serialize=True)

    rbac_config = RBACConfig()  # type: ignore[call-args]

    container = make_rbac_container(rbac_config_instance=rbac_config)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        logger.info("Starting up...")

        print_pd_settings(rbac_config)
        pg_config = await container.get(PGConfig)
        print_pd_settings(pg_config)
        kdb_config = await container.get(KDBConfig)
        print_pd_settings(kdb_config)

        yield

        logger.info("Shutting down...")
        await container.close()

    application = FastAPI(
        debug=rbac_config.DEBUG,
        title=rbac_config.FASTAPI_TITLE,
        lifespan=lifespan,
    )

    fastapi_integration.setup_dishka(container=container, app=application)

    application.include_router(ping_pong_router)
    application.include_router(permission_router)
    application.include_router(role_router)
    application.include_router(session_router)
    application.include_router(user_router)
    application.include_router(token_router)
    application.include_router(auth_router)

    register_error_handler(application)

    return application


app = create_app()
