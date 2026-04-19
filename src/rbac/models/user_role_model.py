from sqlalchemy import ForeignKey, Enum, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from rbac.database import Base

from rbac.enums import PolicyEffectEnum


class UserRole(Base):
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
    )
    role_id: Mapped[int] = mapped_column(
        ForeignKey("roles.id"),
        nullable=False,
    )
    effect: Mapped[PolicyEffectEnum] = mapped_column(
        Enum(PolicyEffectEnum, native_enum=False),
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint("role_id", "user_id"),
    )
