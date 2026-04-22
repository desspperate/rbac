from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import APIRouter, Header, Query, status
from loguru import logger

from rbac.errors import UserPermissionsUpdateIntersectingDeltaError, UserRolesUpdateIntersectingDeltaError
from rbac.models import User
from rbac.schemas import (
    UserCreate,
    UserPermissions,
    UserPermissionsUpdate,
    UserRead,
    UserRoles,
    UserRolesUpdate,
    UsersRead,
    UserUpdate,
)
from rbac.services import UserService

router = APIRouter(
    prefix="/users",
    tags=["Users"],
    route_class=DishkaRoute,
)


@router.get("", response_model=UsersRead)
async def get_users(
        user_service: FromDishka[UserService],
        page: int = Query(default=1, ge=1),
        size: int = Query(default=100, ge=1, le=100),
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> UsersRead:
    with logger.contextualize(user_id=user_id):
        users = await user_service.get_users(page=page, size=size)
        return UsersRead.model_validate({
            "users": users,
        })


@router.get("/{target_user_id}", response_model=UserRead)
async def get_user(
        user_service: FromDishka[UserService],
        target_user_id: int,
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> User:
    with logger.contextualize(user_id=user_id):
        return await user_service.get_user(user_id=target_user_id)


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def create_user(
        user_service: FromDishka[UserService],
        payload: UserCreate,
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> User:
    with logger.contextualize(user_id=user_id):
        return await user_service.create_user(
            username=payload.username,
            password=payload.password,
        )


@router.patch("/{target_user_id}", response_model=UserRead)
async def patch_user(
        user_service: FromDishka[UserService],
        target_user_id: int,
        payload: UserUpdate,
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> User:
    with logger.contextualize(user_id=user_id):
        update_data = payload.model_dump(exclude_unset=True)
        return await user_service.update_user(
            user_id=target_user_id,
            **update_data,
        )


@router.delete("/{target_user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
        user_service: FromDishka[UserService],
        target_user_id: int,
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> None:
    with logger.contextualize(user_id=user_id):
        await user_service.delete_user(user_id=target_user_id)


@router.get("/{target_user_id}/roles", response_model=UserRoles)
async def get_user_roles(
        user_service: FromDishka[UserService],
        target_user_id: int,
        user_id: int | None = Header(None, alias="X-User-Id"),
        page: int = Query(default=1, ge=1),
        size: int = Query(default=100, ge=1, le=100),
) -> UserRoles:
    with logger.contextualize(user_id=user_id):
        roles = await user_service.get_roles(
            user_id=target_user_id,
            page=page,
            size=size,
        )
        return UserRoles.model_validate({
            "user_id": target_user_id,
            "roles": roles,
        })


@router.patch("/{target_user_id}/roles", response_model=UserRoles)
async def patch_user_roles(
        user_service: FromDishka[UserService],
        target_user_id: int,
        payload: UserRolesUpdate,
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> UserRoles:
    with logger.contextualize(user_id=user_id):
        seen: dict[int, tuple[str, int]] = {}
        for i, role in enumerate(payload.set):
            if role.role_id in seen:
                raise UserRolesUpdateIntersectingDeltaError(
                    role_id=role.role_id,
                    delta_1=("set", i),
                    delta_2=seen[role.role_id],
                )
            seen[role.role_id] = ("set", i)
        for i, role_id in enumerate(payload.remove):
            if role_id in seen:
                raise UserRolesUpdateIntersectingDeltaError(
                    role_id=role_id,
                    delta_1=("remove", i),
                    delta_2=seen[role_id],
                )
            seen[role_id] = ("remove", i)

        updated_roles = await user_service.update_roles(
            user_id=target_user_id,
            set_data=[
                {"user_id": target_user_id, "role_id": x.role_id, "effect": x.effect}
                for x in payload.set
            ],
            remove_ids=payload.remove,
        )

        return UserRoles.model_validate({
            "user_id": target_user_id,
            "roles": updated_roles,
        })


@router.get("/{target_user_id}/permissions", response_model=UserPermissions)
async def get_user_permissions(
        user_service: FromDishka[UserService],
        target_user_id: int,
        user_id: int | None = Header(None, alias="X-User-Id"),
        page: int = Query(default=1, ge=1),
        size: int = Query(default=100, ge=1, le=100),
) -> UserPermissions:
    with logger.contextualize(user_id=user_id):
        permissions = await user_service.get_permissions(
            user_id=target_user_id,
            page=page,
            size=size,
        )
        return UserPermissions.model_validate({
            "user_id": target_user_id,
            "permissions": permissions,
        })


@router.patch("/{target_user_id}/permissions", response_model=UserPermissions)
async def patch_user_permissions(
        user_service: FromDishka[UserService],
        target_user_id: int,
        payload: UserPermissionsUpdate,
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> UserPermissions:
    with logger.contextualize(user_id=user_id):
        seen: dict[int, tuple[str, int]] = {}
        for i, perm in enumerate(payload.set):
            if perm.permission_id in seen:
                raise UserPermissionsUpdateIntersectingDeltaError(
                    permission_id=perm.permission_id,
                    delta_1=("set", i),
                    delta_2=seen[perm.permission_id],
                )
            seen[perm.permission_id] = ("set", i)
        for i, permission_id in enumerate(payload.remove):
            if permission_id in seen:
                raise UserPermissionsUpdateIntersectingDeltaError(
                    permission_id=permission_id,
                    delta_1=("remove", i),
                    delta_2=seen[permission_id],
                )
            seen[permission_id] = ("remove", i)

        updated_permissions = await user_service.update_permissions(
            user_id=target_user_id,
            set_data=[
                {"user_id": target_user_id, "permission_id": x.permission_id, "effect": x.effect}
                for x in payload.set
            ],
            remove_ids=payload.remove,
        )

        return UserPermissions.model_validate({
            "user_id": target_user_id,
            "permissions": updated_permissions,
        })
