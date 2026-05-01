from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import APIRouter, Header, Query, status
from loguru import logger

from rbac.actions import RoleAction
from rbac.errors import RolePermissionsUpdateIntersectingDeltaError
from rbac.models import Role
from rbac.schemas import RoleCreate, RolePermissions, RolePermissionsUpdate, RoleRead, RolesRead, RoleUpdate
from rbac.types import RolePatch, RolePermissionsPatch, RolePermissionType

router = APIRouter(
    prefix="/roles",
    tags=["Roles"],
    route_class=DishkaRoute,
)


@router.get("", response_model=RolesRead)
async def get_roles(
        role_action: FromDishka[RoleAction],
        user_id: int | None = Header(None, alias="X-User-Id"),
        page: int = Query(default=1, ge=1),
        size: int = Query(default=100, ge=1, le=100),
) -> RolesRead:
    with logger.contextualize(user_id=user_id):
        roles, total = await role_action.get_roles(page=page, size=size)
        return RolesRead.model_validate({
            "roles": roles,
            "page": page,
            "page_size": size,
            "total": total,
        })


@router.get("/{role_id}", response_model=RoleRead)
async def get_role(
        role_action: FromDishka[RoleAction],
        role_id: int,
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> Role:
    with logger.contextualize(user_id=user_id):
        return await role_action.get_role(role_id=role_id)


@router.post("", response_model=RoleRead, status_code=status.HTTP_201_CREATED)
async def create_role(
        role_action: FromDishka[RoleAction],
        payload: RoleCreate,
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> Role:
    with logger.contextualize(user_id=user_id):
        return await role_action.create_role(
            name=payload.name,
            description=payload.description,
        )


@router.patch("/{role_id}", response_model=RoleRead)
async def patch_role(
        role_action: FromDishka[RoleAction],
        role_id: int,
        payload: RoleUpdate,
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> Role:
    with logger.contextualize(user_id=user_id):
        role_patch = RolePatch(**payload.model_dump(exclude_unset=True))
        return await role_action.update_role(
            role_id=role_id,
            role_patch=role_patch,
        )


@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(
        role_action: FromDishka[RoleAction],
        role_id: int,
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> None:
    with logger.contextualize(user_id=user_id):
        await role_action.delete_role(role_id=role_id)


@router.get("/{role_id}/permissions", response_model=RolePermissions)
async def get_role_permissions(
        role_action: FromDishka[RoleAction],
        role_id: int,
        user_id: int | None = Header(None, alias="X-User-Id"),
        page: int = Query(default=1, ge=1),
        size: int = Query(default=100, ge=1, le=100),
) -> RolePermissions:
    with logger.contextualize(user_id=user_id):
        permissions, total = await role_action.get_role_permissions(
            role_id=role_id,
            page=page,
            size=size,
        )
        return RolePermissions.model_validate({
            "role_id": role_id,
            "permissions": permissions,
            "page": page,
            "page_size": size,
            "total": total,
        })


@router.patch("/{role_id}/permissions", response_model=RolePermissions)
async def patch_role_permissions(
        role_action: FromDishka[RoleAction],
        role_id: int,
        payload: RolePermissionsUpdate,
        user_id: int | None = Header(None, alias="X-User-Id"),
) -> RolePermissions:
    with logger.contextualize(user_id=user_id):
        seen: dict[int, tuple[str, int]] = {}
        for i, perm in enumerate(payload.set):
            if perm.permission_id in seen:
                raise RolePermissionsUpdateIntersectingDeltaError(
                    permission_id=perm.permission_id,
                    delta_1=("set", i),
                    delta_2=seen[perm.permission_id],
                )
            seen[perm.permission_id] = ("set", i)
        for i, permission_id in enumerate(payload.remove):
            if permission_id in seen:
                raise RolePermissionsUpdateIntersectingDeltaError(
                    permission_id=permission_id,
                    delta_1=("remove", i),
                    delta_2=seen[permission_id],
                )
            seen[permission_id] = ("remove", i)

        updated_permissions = await role_action.update_role_permissions(
            role_id=role_id,
            role_permissions_patch=RolePermissionsPatch(
                set=[
                    RolePermissionType(
                        role_id=role_id,
                        permission_id=x.permission_id,
                        effect=x.effect,
                    ) for x in payload.set
                ],
                remove=payload.remove,
            ),
        )

        return RolePermissions.model_validate({
            "role_id": role_id,
            "permissions": updated_permissions,
        })
