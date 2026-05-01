
from dishka.integrations.fastapi import DishkaRoute, FromDishka
from fastapi import APIRouter, Header, Query
from loguru import logger
from starlette import status

from rbac.actions import SessionAction
from rbac.models import Session
from rbac.schemas import SessionCreate, SessionRead, SessionsRead, SessionUpdate
from rbac.types import SessionPatch

router = APIRouter(
    prefix="/sessions",
    tags=["Sessions"],
    route_class=DishkaRoute,
)


@router.get("/{session_id}", response_model=SessionRead)
async def get_session(
        session_id: int,
        session_action: FromDishka[SessionAction],
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> Session:
    with logger.contextualize(user_id=user_id):
        return await session_action.get_session(session_id=session_id)


@router.get("", response_model=SessionsRead)
async def get_sessions(
        session_action: FromDishka[SessionAction],
        page: int = Query(default=1, ge=1),
        size: int = Query(default=100, ge=1, le=100),
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> SessionsRead:
    with logger.contextualize(user_id=user_id):
        sessions, total = await session_action.get_sessions(page=page, size=size)
        return SessionsRead.model_validate({
            "sessions": sessions,
            "page": page,
            "page_size": size,
            "total": total,
        })


@router.post("", status_code=status.HTTP_201_CREATED, response_model=SessionRead)
async def create_session(
        payload: SessionCreate,
        session_action: FromDishka[SessionAction],
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> Session:
    with logger.contextualize(user_id=user_id):
        return await session_action.create_session(
            user_id=payload.user_id,
            forced_status=payload.forced_status,
            user_agent=payload.user_agent,
            ip_address=payload.ip_address,
        )


@router.patch("/{session_id}", response_model=SessionRead)
async def patch_session(
        session_id: int,
        payload: SessionUpdate,
        session_action: FromDishka[SessionAction],
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> Session:
    with logger.contextualize(user_id=user_id):
        session_patch = SessionPatch(**payload.model_dump(exclude_unset=True))
        return await session_action.update_session(
            session_id=session_id,
            session_patch=session_patch,
        )


@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_session(
        session_id: int,
        session_action: FromDishka[SessionAction],
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> None:
    with logger.contextualize(user_id=user_id):
        await session_action.delete_session(session_id=session_id)
