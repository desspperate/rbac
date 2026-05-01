from dishka.integrations.fastapi import DishkaRoute, FromDishka
from fastapi import APIRouter, Header, Query, status
from loguru import logger

from rbac.actions import PermissionAction
from rbac.models import Permission
from rbac.schemas import PermissionCreate, PermissionRead, PermissionsRead, PermissionUpdate
from rbac.types import PermissionPatch

router = APIRouter(
    prefix="/permissions",
    tags=["Permissions"],
    route_class=DishkaRoute,
)


@router.get("", response_model=PermissionsRead)
async def get_permissions(
        permission_action: FromDishka[PermissionAction],
        page: int = Query(default=1, ge=1),
        size: int = Query(default=100, ge=1, le=100),
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> PermissionsRead:
    with logger.contextualize(user_id=user_id):
        permissions, total = await permission_action.get_permissions(page=page, size=size)
        return PermissionsRead.model_validate({
            "permissions": permissions,
            "page": page,
            "page_size": size,
            "total": total,
        })


@router.get("/{permission_id}", response_model=PermissionRead)
async def get_permission(
        permission_action: FromDishka[PermissionAction],
        permission_id: int,
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> Permission:
    with logger.contextualize(user_id=user_id):
        return await permission_action.get_permission(permission_id=permission_id)


@router.post("", response_model=PermissionRead, status_code=status.HTTP_201_CREATED)
async def create_permission(
        permission_action: FromDishka[PermissionAction],
        payload: PermissionCreate,
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> Permission:
    with logger.contextualize(user_id=user_id):
        return await permission_action.create_permission(
            codename=payload.codename,
            description=payload.description,
        )


@router.patch("/{permission_id}", response_model=PermissionRead)
async def patch_permission(
        permission_action: FromDishka[PermissionAction],
        permission_id: int,
        payload: PermissionUpdate,
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> Permission:
    with logger.contextualize(user_id=user_id):
        permission_patch = PermissionPatch(**payload.model_dump(exclude_unset=True))
        return await permission_action.update_permission(
            permission_id=permission_id,
            permission_patch=permission_patch,
        )


@router.delete("/{permission_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_permission(
        permission_action: FromDishka[PermissionAction],
        permission_id: int,
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> None:
    with logger.contextualize(user_id=user_id):
        await permission_action.delete_permission(permission_id=permission_id)
