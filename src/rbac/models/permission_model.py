from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from rbac.constants import RBACConstants
from rbac.database import Base

if TYPE_CHECKING:
    from rbac.models import Role, User


class Permission(Base):
    codename: Mapped[str] = mapped_column(
        String(RBACConstants.PERMISSION_CODENAME_MAX_LEN),
        nullable=False,
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

    CK_PERMISSION_CODENAME_PATTERN = "ck_permission_codename_pattern"
    CK_PERMISSION_DESCRIPTION_PATTERN = "ck_permission_description_pattern"
    UQ_PERMISSION_CODENAME = "uq_permission_codename"

    __table_args__ = (
        CheckConstraint(
            fr"codename ~ '{RBACConstants.PERMISSION_CODENAME_PATTERN}'",
            name=CK_PERMISSION_CODENAME_PATTERN,
        ),
        CheckConstraint(
            fr"description ~ '{RBACConstants.DESCRIPTION_PATTERN}'",
            name=CK_PERMISSION_DESCRIPTION_PATTERN,
        ),
        UniqueConstraint(
            "codename",
            name=UQ_PERMISSION_CODENAME,
        ),
    )
