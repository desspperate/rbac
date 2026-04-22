from sqlalchemy import Enum, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from rbac.database import Base
from rbac.enums import PolicyEffectEnum


class UserRole(Base):
    FK_USER_ROLE_USER_ID = "fk_user_role_user_id"
    FK_USER_ROLE_ROLE_ID = "fk_user_role_role_id"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", name=FK_USER_ROLE_USER_ID),
        nullable=False,
    )
    role_id: Mapped[int] = mapped_column(
        ForeignKey("roles.id", name=FK_USER_ROLE_ROLE_ID),
        nullable=False,
    )
    effect: Mapped[PolicyEffectEnum] = mapped_column(
        Enum(PolicyEffectEnum, native_enum=False),
        nullable=False,
    )

    UQ_USER_ROLE_USER_ROLE = "uq_user_role_user_role"

    __table_args__ = (
        UniqueConstraint("role_id", "user_id", name=UQ_USER_ROLE_USER_ROLE),
    )
