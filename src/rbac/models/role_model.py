from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from rbac.constants import RBACConstants
from rbac.database import Base

if TYPE_CHECKING:
    from rbac.models import Permission, User


class Role(Base):
    name: Mapped[str] = mapped_column(String(RBACConstants.ROLE_NAME_MAX_LEN), nullable=False)
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

    CK_ROLE_NAME_PATTERN = "ck_role_name_pattern"
    CK_ROLE_DESCRIPTION_PATTERN = "ck_role_description_pattern"
    UQ_ROLE_NAME = "uq_role_name"

    __table_args__ = (
        CheckConstraint(
            fr"name ~ '{RBACConstants.ROLE_NAME_PATTERN}'",
            name=CK_ROLE_NAME_PATTERN,
        ),
        CheckConstraint(
            fr"description ~ '{RBACConstants.DESCRIPTION_PATTERN}'",
            name=CK_ROLE_DESCRIPTION_PATTERN,
        ),
        UniqueConstraint(
            "name",
            name=UQ_ROLE_NAME,
        ),
    )
