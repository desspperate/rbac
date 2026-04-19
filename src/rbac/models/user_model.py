from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from rbac.database import Base
from rbac.constants import RBACConstants

if TYPE_CHECKING:
    from rbac.models import Role, Permission, Token


class User(Base):
    username: Mapped[str] = mapped_column(
        String(RBACConstants.USER_USERNAME_MAX_LEN),
        nullable=False,
        unique=True,
    )
    password_hash: Mapped[str] = mapped_column(
        String(RBACConstants.HASH_LEN),
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

    __table_args__ = (
        CheckConstraint(
            fr"username ~ '{RBACConstants.USER_USERNAME_PATTERN}'",
            name="username_pattern",
        ),
    )
