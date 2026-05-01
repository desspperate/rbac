from dishka.integrations.fastapi import DishkaRoute, FromDishka
from fastapi import APIRouter, Header, Query, Request
from pydantic import SecretStr
from starlette import status

from rbac.actions import AuthAction
from rbac.schemas import LoginRequest, MeResponse, RefreshRequest, RegisterRequest, TokenPair
from rbac.types import UserIdentityType
from rbac.utils import get_bearer_token, get_request_metadata

router = APIRouter(
    prefix="/auth",
    tags=["Auth"],
    route_class=DishkaRoute,
)


Authorization = Header(alias="Authorization")


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
    return TokenPair.model_validate(token_pair)


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
    return TokenPair.model_validate(token_pair)


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
    return TokenPair.model_validate(token_pair)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
        auth_action: FromDishka[AuthAction],
        access_token: SecretStr = Authorization,
) -> None:
    access_token = get_bearer_token(bearer=access_token)
    await auth_action.logout(access_token=access_token)


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(
        auth_action: FromDishka[AuthAction],
        access_token: SecretStr = Authorization,
        *,
        exclude_current: bool = Query(default=False),
) -> None:
    access_token = get_bearer_token(bearer=access_token)
    await auth_action.logout_all(access_token=access_token, exclude_current=exclude_current)


@router.get("/me", response_model=MeResponse)
async def me(
        auth_action: FromDishka[AuthAction],
        access_token: SecretStr = Authorization,
) -> UserIdentityType:
    access_token = get_bearer_token(bearer=access_token)
    return await auth_action.get_user_identity(access_token=access_token)
