from .permission_router import router as permission_router
from .ping_pong_router import router as ping_pong_router
from .role_router import router as role_router
from .token_router import router as token_router
from .user_router import router as user_router

__all__ = [
    "permission_router",
    "ping_pong_router",
    "role_router",
    "token_router",
    "user_router",
]
