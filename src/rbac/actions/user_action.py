from collections.abc import Sequence

from loguru import logger
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.models import User, UserPermission, UserRole
from rbac.services import UserService
from rbac.types import UserPatch, UserPermissionsPatch, UserRolesPatch


class UserAction:
    def __init__(
            self,
            session: AsyncSession,
            user_service: UserService,
    ) -> None:
        self.session = session
        self.user_service = user_service

    async def create_user(self, username: str, password: SecretStr) -> User:
        new_user = await self.user_service.create_user(username=username, password=password)
        await self.session.commit()
        logger.info(f"User created: id={new_user.id} username='{username}'")
        return new_user

    async def get_user(self, user_id: int) -> User:
        user = await self.user_service.get_user(user_id=user_id)
        logger.info(f"Found user with: id={user.username}, username='{user.username}'")
        return user

    async def get_users(self, page: int, size: int) -> tuple[Sequence[User], int]:
        result = await self.user_service.get_users(page=page, size=size)
        logger.info(f"Found {len(result[0])} users")
        return result

    async def delete_user(self, user_id: int) -> None:
        await self.user_service.delete_user(user_id=user_id)
        await self.session.commit()
        logger.info(f"User deleted: {user_id}")

    async def update_user(
            self,
            user_id: int,
            user_patch: UserPatch,
    ) -> User:
        user = await self.user_service.update_user(
            user_id=user_id,
            user_patch=user_patch,
        )
        await self.session.commit()
        logger.info(f"User updated: {user_id}")
        return user

    async def update_user_roles(
            self,
            user_id: int,
            user_roles_patch: UserRolesPatch,
    ) -> Sequence[UserRole]:
        user_roles = await self.user_service.update_user_roles(
            user_id=user_id,
            user_roles_patch=user_roles_patch,
        )
        await self.session.commit()
        logger.info(f"Roles updated for user: {user_id}")
        return user_roles

    async def get_user_roles(self, user_id: int, page: int, size: int) -> tuple[Sequence[UserRole], int]:
        result = await self.user_service.get_roles(user_id=user_id, page=page, size=size)
        logger.info(f"Found {len(result[0])} user: {user_id} roles")
        return result

    async def update_user_permissions(
            self,
            user_id: int,
            user_permissions_patch: UserPermissionsPatch,
    ) -> Sequence[UserPermission]:
        user_roles = await self.user_service.update_user_permissions(
            user_id=user_id,
            user_permissions_patch=user_permissions_patch,
        )
        await self.session.commit()
        logger.info(f"Permissions updated for user: {user_id}")
        return user_roles

    async def get_user_permissions(
            self,
            user_id: int,
            page: int,
            size: int,
    ) -> tuple[Sequence[UserPermission], int]:
        result = await self.user_service.get_permissions(user_id=user_id, page=page, size=size)
        logger.info(f"Found {len(result[0])} permissions")
        return result
