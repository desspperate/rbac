from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager

from asyncpg import CheckViolationError, NotNullViolationError, UniqueViolationError
from asyncpg.exceptions import ForeignKeyViolationError
from loguru import logger
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.constants import RBACConstants
from rbac.enums import PolicyEffectEnum
from rbac.errors import (
    PermissionNotFoundError,
    PermissionsNotFoundError,
    RoleNotFoundError,
    RolesNotFoundError,
    UnhandledIntegrityError,
    UserNotFoundError,
    UserPasswordNullError,
    UserStillReferencedError,
    UserUsernameAlreadyExistError,
    UserUsernameInvalidError,
    UserUsernameNullError,
)
from rbac.models import Token, User, UserPermission, UserRole
from rbac.repositories import UserPermissionRepository, UserRepository, UserRoleRepository
from rbac.utils import UNSET, HandleIntegrityHelpers, Unset, crypto_hash, get_asyncpg_error


@asynccontextmanager
async def handle_user_integrity(username: str | None) -> AsyncIterator[None]:
    try:
        yield
    except IntegrityError as e:
        asyncpg_error = get_asyncpg_error(e)
        if asyncpg_error is None:
            raise UnhandledIntegrityError from e

        if isinstance(asyncpg_error, CheckViolationError | UniqueViolationError | ForeignKeyViolationError):
            constraint = HandleIntegrityHelpers.get_constraint(asyncpg_error, e)

            if constraint == User.UQ_USER_USERNAME and isinstance(username, str):
                raise UserUsernameAlreadyExistError(username=username) from e
            if constraint == User.CK_USER_USERNAME_PATTERN and isinstance(username, str):
                raise UserUsernameInvalidError(username=username, pattern=RBACConstants.USER_USERNAME_PATTERN) from e

            if isinstance(asyncpg_error, ForeignKeyViolationError):
                _, failed_value, referrer_table = HandleIntegrityHelpers.get_details(asyncpg_error, e)

                if constraint in {
                    Token.FK_TOKEN_USER_ID,
                    UserRole.FK_USER_ROLE_USER_ID,
                    UserPermission.FK_USER_PERMISSION_USER_ID,
                }:
                    raise UserStillReferencedError(
                        user_id=failed_value,
                        related_object_type=referrer_table,
                    ) from e
        elif isinstance(asyncpg_error, NotNullViolationError):
            column = HandleIntegrityHelpers.get_column(asyncpg_error, e)

            if column == "username":
                raise UserUsernameNullError from e
            if column == "password_hash":
                raise UserPasswordNullError from e

        raise UnhandledIntegrityError from e


@asynccontextmanager
async def handle_user_role_integrity() -> AsyncIterator[None]:
    try:
        yield
    except IntegrityError as e:
        asyncpg_error = get_asyncpg_error(e)
        if asyncpg_error is None:
            raise UnhandledIntegrityError from e

        constraint = HandleIntegrityHelpers.get_constraint(asyncpg_error, e)

        if isinstance(asyncpg_error, ForeignKeyViolationError):
            _, failed_value, _ = HandleIntegrityHelpers.get_details(asyncpg_error, e)

            if constraint == UserRole.FK_USER_ROLE_USER_ID:
                raise UserNotFoundError(user_id=failed_value) from e
            if constraint == UserRole.FK_USER_ROLE_ROLE_ID:
                raise RoleNotFoundError(role_id=failed_value) from e

        raise UnhandledIntegrityError from e


@asynccontextmanager
async def handle_user_permission_integrity() -> AsyncIterator[None]:
    try:
        yield
    except IntegrityError as e:
        asyncpg_error = get_asyncpg_error(e)
        if asyncpg_error is None:
            raise UnhandledIntegrityError from e

        constraint = HandleIntegrityHelpers.get_constraint(asyncpg_error, e)

        if isinstance(asyncpg_error, ForeignKeyViolationError):
            _, failed_value, _ = HandleIntegrityHelpers.get_details(asyncpg_error, e)

            if constraint == UserPermission.FK_USER_PERMISSION_USER_ID:
                raise UserNotFoundError(user_id=failed_value) from e
            if constraint == UserPermission.FK_USER_PERMISSION_PERMISSION_ID:
                raise PermissionNotFoundError(permission_id=failed_value) from e

        raise UnhandledIntegrityError from e


class UserService:
    def __init__(
            self,
            session: AsyncSession,
            user_repository: UserRepository,
            user_role_repository: UserRoleRepository,
            user_permission_repository: UserPermissionRepository,
    ) -> None:
        self.session = session
        self.user_repository = user_repository
        self.user_role_repository = user_role_repository
        self.user_permission_repository = user_permission_repository

    async def create_user(
            self,
            username: str,
            password: str,
    ) -> User:
        logger.info(f"Creating user: username='{username}'")
        password_hash = crypto_hash(password)
        async with handle_user_integrity(username=username):
            user = await self.user_repository.create_user(
                username=username,
                password_hash=password_hash,
            )
            await self.session.commit()
        logger.info(f"User created: {user.id}")
        return user

    async def get_users(self, page: int, size: int) -> tuple[Sequence[User], int]:
        logger.info(f"Getting users for page: {page}, size: {size}")
        return await self.user_repository.list_all(skip=(page - 1) * size, limit=size)

    async def get_user(self, user_id: int) -> User:
        logger.info(f"Getting user: {user_id}")
        if (user := await self.user_repository.get_by_id(user_id)) is None:
            raise UserNotFoundError(user_id=user_id)
        return user

    async def delete_user(self, user_id: int) -> None:
        logger.info(f"Deleting user: {user_id}")
        async with handle_user_integrity(username=None):
            deleted = await self.user_repository.delete_by_id(user_id)
        if not deleted:
            raise UserNotFoundError(user_id=user_id)
        await self.session.commit()
        logger.info(f"User deleted: {user_id}")

    async def update_user(
            self,
            user_id: int,
            username: str | Unset = UNSET,
            password: str | Unset = UNSET,
    ) -> User:
        logger.info(f"Updating user: {user_id}")
        user = await self.get_user(user_id)

        if not isinstance(username, Unset):
            user.username = username
        if not isinstance(password, Unset):
            user.password_hash = crypto_hash(password)

        async with handle_user_integrity(username=username if not isinstance(username, Unset) else None):
            await self.session.commit()
        await self.session.refresh(user)
        logger.info(f"User updated: {user_id}")
        return user

    async def update_roles(
            self,
            user_id: int,
            set_data: list[dict[str, int | PolicyEffectEnum]],
            remove_ids: Sequence[int],
    ) -> Sequence[UserRole]:
        logger.info(f"Updating roles for user: {user_id}")
        async with handle_user_role_integrity():
            not_deleted = await self.user_role_repository.remove_user_roles(user_id=user_id, remove_ids=remove_ids)
            if not_deleted:
                raise RolesNotFoundError(role_ids=not_deleted)
            await self.user_role_repository.upsert_user_roles(set_data=set_data)
            await self.session.commit()
        logger.info(f"Roles updated for user: {user_id}")
        return await self.user_role_repository.get_user_roles(user_id=user_id)

    async def get_roles(self, user_id: int, page: int, size: int) -> tuple[Sequence[UserRole], int]:
        logger.info(f"Getting roles for user: {user_id}, page: {page}, size: {size}")
        return await self.user_role_repository.list_all(
            skip=(page - 1) * size,
            limit=size,
            user_id=user_id,
        )

    async def update_permissions(
            self,
            user_id: int,
            set_data: list[dict[str, int | PolicyEffectEnum]],
            remove_ids: Sequence[int],
    ) -> Sequence[UserPermission]:
        logger.info(f"Updating permissions for user: {user_id}")
        async with handle_user_permission_integrity():
            not_deleted = await self.user_permission_repository.remove_user_permissions(
                user_id=user_id,
                remove_ids=remove_ids,
            )
            if not_deleted:
                raise PermissionsNotFoundError(permission_ids=not_deleted)
            await self.user_permission_repository.upsert_user_permissions(set_data=set_data)
            await self.session.commit()
        logger.info(f"Permissions updated for user: {user_id}")
        return await self.user_permission_repository.get_user_permissions(user_id=user_id)

    async def get_permissions(self, user_id: int, page: int, size: int) -> tuple[Sequence[UserPermission], int]:
        logger.info(f"Getting permissions for user: {user_id}, page: {page}, size: {size}")
        return await self.user_permission_repository.list_all(
            skip=(page - 1) * size,
            limit=size,
            user_id=user_id,
        )
