from dishka.integrations.fastapi import DishkaRoute, FromDishka
from fastapi import APIRouter, Header, Query
from loguru import logger
from starlette import status

from rbac.models import Token
from rbac.schemas import TokenCreate, TokenPrivateRead, TokenRead, TokensRead, TokenUpdate
from rbac.services.token_service import TokenService

router = APIRouter(
    prefix="/tokens",
    tags=["Tokens"],
    route_class=DishkaRoute,
)


@router.get("/{token_id}", response_model=TokenRead)
async def get_token(
        token_id: int,
        token_service: FromDishka[TokenService],
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> Token:
    with logger.contextualize(user_id=user_id):
        return await token_service.get_token(token_id=token_id)


@router.get("", response_model=TokensRead)
async def get_tokens(
        token_service: FromDishka[TokenService],
        page: int = Query(default=1, ge=1),
        size: int = Query(default=100, ge=1, le=100),
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> TokensRead:
    with logger.contextualize(user_id=user_id):
        tokens, total = await token_service.get_tokens(page=page, size=size)
        return TokensRead.model_validate({
            "tokens": tokens,
            "page": page,
            "page_size": size,
            "total": total,
        })


@router.post("", status_code=status.HTTP_201_CREATED, response_model=TokenPrivateRead)
async def create_token(
    payload: TokenCreate,
    token_service: FromDishka[TokenService],
    user_id: int | None = Header(None, alias="X-User-Id"),
) -> TokenPrivateRead:
    with logger.contextualize(user_id=user_id):
        return await token_service.create_token(
            user_id=payload.user_id,
            provided_token=payload.token_value,
            token_type=payload.token_type,
            forced_status=payload.forced_status,
            expires_at_=payload.expires_at,
        )


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_token(
        token_id: int,
        token_service: FromDishka[TokenService],
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> None:
    with logger.contextualize(user_id=user_id):
        await token_service.delete_token(token_id=token_id)


@router.patch("/{token_id}", response_model=TokenRead)
async def patch_token(
        token_id: int,
        payload: TokenUpdate,
        token_service: FromDishka[TokenService],
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> Token:
    with logger.contextualize(user_id=user_id):
        update_data = payload.model_dump(exclude_unset=True)
        return await token_service.update_token(
            token_id=token_id,
            **update_data,
        )
