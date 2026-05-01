from dishka.integrations.fastapi import DishkaRoute, FromDishka
from fastapi import APIRouter, Request
from starlette import status

from rbac.actions import AuthAction
from rbac.schemas import LoginRequest, RefreshRequest, RegisterRequest, TokenPair
from rbac.utils import get_request_metadata

router = APIRouter(
    prefix="/auth",
    tags=["Auth"],
    route_class=DishkaRoute,
)


@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=TokenPair)
async def register(
        payload: RegisterRequest,
        request: Request,
        auth_action: FromDishka[AuthAction],
) -> TokenPair:
    user_agent, ip_address = get_request_metadata(request)
    token_pair = await auth_action.register(
        username=payload.username,
        password=payload.password,
        user_agent=user_agent,
        ip_address=ip_address,
    )
    return TokenPair(**token_pair)


@router.post("/login", status_code=status.HTTP_201_CREATED, response_model=TokenPair)
async def login(
        payload: LoginRequest,
        request: Request,
        auth_action: FromDishka[AuthAction],
) -> TokenPair:
    user_agent, ip_address = get_request_metadata(request)
    token_pair = await auth_action.login(
        username=payload.username,
        password=payload.password,
        user_agent=user_agent,
        ip_address=ip_address,
    )
    return TokenPair(**token_pair)


@router.post("/refresh", status_code=status.HTTP_201_CREATED, response_model=TokenPair)
async def refresh(
        payload: RefreshRequest,
        request: Request,
        auth_action: FromDishka[AuthAction],
) -> TokenPair:
    user_agent, ip_address = get_request_metadata(request)
    token_pair = await auth_action.refresh(
        access_token=payload.access_token,
        refresh_token=payload.refresh_token,
        user_agent=user_agent,
        ip_address=ip_address,
    )
    return TokenPair(**token_pair)
