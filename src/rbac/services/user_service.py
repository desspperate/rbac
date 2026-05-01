from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager

from asyncpg import CheckViolationError, NotNullViolationError, UniqueViolationError
from asyncpg.exceptions import ForeignKeyViolationError
from loguru import logger
from pydantic import SecretStr
from sqlalchemy.exc import IntegrityError

from rbac.constants import RBACConstants
from rbac.errors import (
    PermissionNotFoundError,
    PermissionsNotFoundError,
    RoleNotFoundError,
    RolesNotFoundError,
    UnhandledIntegrityError,
    UserNotFoundByIDError,
    UserNotFoundByUsernameError,
    UserPasswordNullError,
    UserStillReferencedError,
    UserUsernameAlreadyExistError,
    UserUsernameInvalidError,
    UserUsernameNullError,
)
from rbac.models import Session, User, UserPermission, UserRole
from rbac.repositories import UserPermissionRepository, UserRepository, UserRoleRepository
from rbac.types import UserPatch, UserPermissionsPatch, UserRolesPatch
from rbac.utils import HandleIntegrityHelpers, crypto_hash, get_asyncpg_error


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
                    Session.FK_SESSION_USER_ID,
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
                raise UserNotFoundByIDError(user_id=failed_value) from e
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
                raise UserNotFoundByIDError(user_id=failed_value) from e
            if constraint == UserPermission.FK_USER_PERMISSION_PERMISSION_ID:
                raise PermissionNotFoundError(permission_id=failed_value) from e

        raise UnhandledIntegrityError from e


class UserService:
    def __init__(
            self,
            user_repository: UserRepository,
            user_role_repository: UserRoleRepository,
            user_permission_repository: UserPermissionRepository,
    ) -> None:
        self.user_repository = user_repository
        self.user_role_repository = user_role_repository
        self.user_permission_repository = user_permission_repository

    async def create_user(
            self,
            username: str,
            password: SecretStr,
    ) -> User:
        logger.info(f"Creating user with username '{username}'")
        password_hash = await crypto_hash(password.get_secret_value())
        async with handle_user_integrity(username=username):
            return await self.user_repository.create_user(
                username=username,
                password_hash=password_hash,
            )

    async def get_users(self, page: int, size: int) -> tuple[Sequence[User], int]:
        logger.info(f"Getting users for page: {page}, size: {size}")
        return await self.user_repository.list_all(skip=(page - 1) * size, limit=size)

    async def get_user(self, user_id: int) -> User:
        logger.info(f"Getting user: {user_id}")
        if (user := await self.user_repository.get_by_id(user_id)) is None:
            raise UserNotFoundByIDError(user_id=user_id)
        return user

    async def delete_user(self, user_id: int) -> None:
        logger.info(f"Deleting user: {user_id}")
        async with handle_user_integrity(username=None):
            deleted = await self.user_repository.delete_by_id(user_id)
        if not deleted:
            raise UserNotFoundByIDError(user_id=user_id)

    async def update_user(
            self,
            user_id: int,
            user_patch: UserPatch,
    ) -> User:
        logger.info(f"Updating user: {user_id}")

        password = user_patch.pop("password", None)
        if isinstance(password, SecretStr):
            user_patch["password_hash"] = await crypto_hash(password.get_secret_value())

        async with handle_user_integrity(username=user_patch.get("username")):
            return await self.user_repository.update_user(
                user_id=user_id,
                user_patch=user_patch,
            )

    async def update_user_roles(
            self,
            user_id: int,
            user_roles_patch: UserRolesPatch,
    ) -> Sequence[UserRole]:
        logger.info(f"Updating roles for user: {user_id}")
        async with handle_user_role_integrity():
            not_deleted = await self.user_role_repository.remove_user_roles(
                user_id=user_id,
                remove_ids=user_roles_patch.get("remove", []),
            )
            if not_deleted:
                raise RolesNotFoundError(role_ids=not_deleted)
            await self.user_role_repository.upsert_user_roles(set_data=user_roles_patch.get("set", {}))
        return await self.user_role_repository.get_user_roles(user_id=user_id)

    async def get_roles(self, user_id: int, page: int, size: int) -> tuple[Sequence[UserRole], int]:
        logger.info(f"Getting roles for user: {user_id}, page: {page}, size: {size}")
        return await self.user_role_repository.list_all(
            skip=(page - 1) * size,
            limit=size,
            user_id=user_id,
        )

    async def update_user_permissions(
            self,
            user_id: int,
            user_permissions_patch: UserPermissionsPatch,
    ) -> Sequence[UserPermission]:
        logger.info(f"Updating permissions for user: {user_id}")
        async with handle_user_permission_integrity():
            not_deleted = await self.user_permission_repository.remove_user_permissions(
                user_id=user_id,
                remove_ids=user_permissions_patch.get("remove", []),
            )
            if not_deleted:
                raise PermissionsNotFoundError(permission_ids=not_deleted)
            await self.user_permission_repository.upsert_user_permissions(
                set_data=user_permissions_patch.get("set", {}),
            )
        return await self.user_permission_repository.get_user_permissions(user_id=user_id)

    async def get_permissions(self, user_id: int, page: int, size: int) -> tuple[Sequence[UserPermission], int]:
        logger.info(f"Getting permissions for user: {user_id}, page: {page}, size: {size}")
        return await self.user_permission_repository.list_all(
            skip=(page - 1) * size,
            limit=size,
            user_id=user_id,
        )

    async def find_by_username(self, username: str) -> User:
        logger.info(f"Finding user with username: {username}")
        if (user := await self.user_repository.get_by_username(username=username)) is None:
            raise UserNotFoundByUsernameError(username=username)
        return user
