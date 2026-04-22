import hashlib
import os
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
    UserUsernameAlreadyExistError,
    UserUsernameInvalidError,
    UserUsernameNullError,
)
from rbac.models import User, UserPermission, UserRole
from rbac.repositories import UserRepository
from rbac.utils import FK_DETAIL_PATTERN, UNSET, Unset, get_asyncpg_error


def _hash_password(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=2**5)
    return salt.hex() + ":" + key.hex()


@asynccontextmanager
async def handle_user_integrity(username: str | None) -> AsyncIterator[None]:
    try:
        yield
    except IntegrityError as e:
        asyncpg_error = get_asyncpg_error(e)
        if asyncpg_error is None:
            raise UnhandledIntegrityError from e

        if isinstance(asyncpg_error, CheckViolationError | UniqueViolationError):
            constraint = getattr(asyncpg_error, "constraint_name", None)
            if not isinstance(constraint, str):
                raise UnhandledIntegrityError from e

            if constraint == User.UQ_USER_USERNAME and isinstance(username, str):
                raise UserUsernameAlreadyExistError(username=username) from e
            if constraint == User.CK_USER_USERNAME_PATTERN and isinstance(username, str):
                raise UserUsernameInvalidError(username=username, pattern=RBACConstants.USER_USERNAME_PATTERN) from e
        elif isinstance(asyncpg_error, NotNullViolationError):
            column = getattr(asyncpg_error, "column_name", None)
            if not isinstance(column, str):
                raise UnhandledIntegrityError from e

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

        constraint = getattr(asyncpg_error, "constraint_name", None)
        if not isinstance(constraint, str):
            raise UnhandledIntegrityError from e

        if isinstance(asyncpg_error, ForeignKeyViolationError):
            detail = getattr(asyncpg_error, "detail", "")
            failed_value = None
            match = FK_DETAIL_PATTERN.search(detail)
            if match:
                try:
                    failed_value = int(match.group(2))
                except (ValueError, TypeError):
                    raise UnhandledIntegrityError from e
            if not isinstance(failed_value, int):
                raise UnhandledIntegrityError from e

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

        constraint = getattr(asyncpg_error, "constraint_name", None)
        if not isinstance(constraint, str):
            raise UnhandledIntegrityError from e

        if isinstance(asyncpg_error, ForeignKeyViolationError):
            detail = getattr(asyncpg_error, "detail", "")
            failed_value = None
            match = FK_DETAIL_PATTERN.search(detail)
            if match:
                try:
                    failed_value = int(match.group(2))
                except ValueError:
                    raise UnhandledIntegrityError from e
            if not isinstance(failed_value, int):
                raise UnhandledIntegrityError from e

            if constraint == UserPermission.FK_USER_PERMISSION_USER_ID:
                raise UserNotFoundError(user_id=failed_value) from e
            if constraint == UserPermission.FK_USER_PERMISSION_PERMISSION_ID:
                raise PermissionNotFoundError(permission_id=failed_value) from e

        raise UnhandledIntegrityError from e


class UserService:
    def __init__(self, session: AsyncSession, user_repository: UserRepository) -> None:
        self.session = session
        self.user_repository = user_repository

    async def create_user(
            self,
            username: str,
            password: str,
    ) -> User:
        logger.info(f"Creating user: username='{username}'")
        password_hash = _hash_password(password)
        async with handle_user_integrity(username=username):
            user = await self.user_repository.create_user(
                username=username,
                password_hash=password_hash,
            )
            await self.session.commit()
        logger.info(f"User created: {user.id}")
        return user

    async def get_users(self, page: int, size: int) -> Sequence[User]:
        logger.info(f"Getting users for page: {page}, size: {size}")
        return await self.user_repository.list_all(skip=(page - 1) * size, limit=size)

    async def get_user(self, user_id: int) -> User:
        logger.info(f"Getting user: {user_id}")
        if (user := await self.user_repository.get_by_id(user_id)) is None:
            raise UserNotFoundError(user_id=user_id)
        return user

    async def delete_user(self, user_id: int) -> None:
        logger.info(f"Deleting user: {user_id}")
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
            user.password_hash = _hash_password(password)

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
            not_deleted = await self.user_repository.remove_roles(user_id=user_id, remove_ids=remove_ids)
            if not_deleted:
                raise RolesNotFoundError(role_ids=not_deleted)
            await self.user_repository.upsert_roles(set_data=set_data)
            await self.session.commit()
        logger.info(f"Roles updated for user: {user_id}")
        return await self.user_repository.get_roles(user_id=user_id)

    async def get_roles(self, user_id: int, page: int, size: int) -> Sequence[UserRole]:
        logger.info(f"Getting roles for user: {user_id}, page: {page}, size: {size}")
        return await self.user_repository.list_roles(user_id=user_id, skip=(page - 1) * size, limit=size)

    async def update_permissions(
            self,
            user_id: int,
            set_data: list[dict[str, int | PolicyEffectEnum]],
            remove_ids: Sequence[int],
    ) -> Sequence[UserPermission]:
        logger.info(f"Updating permissions for user: {user_id}")
        async with handle_user_permission_integrity():
            not_deleted = await self.user_repository.remove_permissions(user_id=user_id, remove_ids=remove_ids)
            if not_deleted:
                raise PermissionsNotFoundError(permission_ids=not_deleted)
            await self.user_repository.upsert_permissions(set_data=set_data)
            await self.session.commit()
        logger.info(f"Permissions updated for user: {user_id}")
        return await self.user_repository.get_permissions(user_id=user_id)

    async def get_permissions(self, user_id: int, page: int, size: int) -> Sequence[UserPermission]:
        logger.info(f"Getting permissions for user: {user_id}, page: {page}, size: {size}")
        return await self.user_repository.list_permissions(user_id=user_id, skip=(page - 1) * size, limit=size)
