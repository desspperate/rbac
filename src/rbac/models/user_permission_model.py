from sqlalchemy import Enum, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from rbac.database import Base
from rbac.enums import PolicyEffectEnum


class UserPermission(Base):
    FK_USER_PERMISSION_USER_ID = "fk_user_permission_user_id"
    FK_USER_PERMISSION_PERMISSION_ID = "fk_user_permission_permission_id"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", name=FK_USER_PERMISSION_USER_ID),
        nullable=False,
    )
    permission_id: Mapped[int] = mapped_column(
        ForeignKey("permissions.id", name=FK_USER_PERMISSION_PERMISSION_ID),
        nullable=False,
    )
    effect: Mapped[PolicyEffectEnum] = mapped_column(
        Enum(PolicyEffectEnum, native_enum=False),
        nullable=False,
    )

    UQ_USER_PERMISSION_USER_PERMISSION = "uq_user_permission_user_permission"

    __table_args__ = (
        UniqueConstraint("user_id", "permission_id", name=UQ_USER_PERMISSION_USER_PERMISSION),
    )
