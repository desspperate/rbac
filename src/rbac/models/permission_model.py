from typing import TYPE_CHECKING

from sqlalchemy import String, CheckConstraint
from sqlalchemy.orm import mapped_column, relationship, Mapped

from rbac.database import Base
from rbac.constants import RBACConstants

if TYPE_CHECKING:
    from rbac.models import User, Role


class Permission(Base):
    codename: Mapped[str] = mapped_column(
        String(RBACConstants.PERMISSION_CODENAME_MAX_LEN),
        nullable=False,
        unique=True,
    )
    description: Mapped[str | None] = mapped_column(
        String(RBACConstants.PERMISSION_DESCRIPTION_MAX_LEN),
        nullable=True,
    )

    users: Mapped[list["User"]] = relationship(
        "User",
        secondary="user_permissions",
        back_populates="permissions",
    )
    roles: Mapped[list["Role"]] = relationship(
        "Role",
        secondary="role_permissions",
        back_populates="permissions",
    )

    __table_args__ = (
        CheckConstraint(
            fr"codename ~ '{RBACConstants.PERMISSION_CODENAME_PATTERN}'",
            name="codename_pattern",
        ),
    )
