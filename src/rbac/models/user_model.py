from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from rbac.constants import RBACConstants
from rbac.database import Base

if TYPE_CHECKING:
    from rbac.models import Permission, Role, Token


class User(Base):
    username: Mapped[str] = mapped_column(
        String(RBACConstants.USER_USERNAME_MAX_LEN),
        nullable=False,
    )
    password_hash: Mapped[str] = mapped_column(
        String(RBACConstants.HASH_MAX_LEN),
        nullable=False,
    )

    tokens: Mapped[list["Token"]] = relationship(
        "Token",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    roles: Mapped[list["Role"]] = relationship(
        "Role",
        secondary="user_roles",
        back_populates="users",
    )
    permissions: Mapped[list["Permission"]] = relationship(
        "Permission",
        secondary="user_permissions",
        back_populates="users",
    )

    CK_USER_USERNAME_PATTERN = "ck_user_username_pattern"
    UQ_USER_USERNAME = "uq_user_username"

    __table_args__ = (
        CheckConstraint(
            fr"username ~ '{RBACConstants.USER_USERNAME_PATTERN}'",
            name=CK_USER_USERNAME_PATTERN,
        ),
        UniqueConstraint(
            "username",
            name=UQ_USER_USERNAME,
        ),
    )
