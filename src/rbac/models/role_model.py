from typing import TYPE_CHECKING

from sqlalchemy import String, CheckConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from rbac.database import Base
from rbac.constants import RBACConstants

if TYPE_CHECKING:
    from rbac.models import User, Permission


class Role(Base):
    name: Mapped[str] = mapped_column(String(RBACConstants.ROLE_NAME_MAX_LEN), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(String(RBACConstants.ROLE_DESCRIPTION_MAX_LEN), nullable=True)

    users: Mapped[list["User"]] = relationship(
        "User",
        secondary="user_roles",
        back_populates="roles",
    )
    permissions: Mapped[list["Permission"]] = relationship(
        "Permission",
        secondary="role_permissions",
        back_populates="roles",
    )

    __table_args__ = (
        CheckConstraint(
            fr"name ~ '{RBACConstants.ROLE_NAME_PATTERN}'",
            name="name_pattern",
        ),
    )
