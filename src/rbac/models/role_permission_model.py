from sqlalchemy import Enum, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from rbac.database import Base
from rbac.enums import PolicyEffectEnum


class RolePermission(Base):
    FK_ROLE_PERMISSION_ROLE_ID = "fk_role_permission_role_id"
    FK_ROLE_PERMISSION_PERMISSION_ID = "fk_role_permission_permission_id"

    role_id: Mapped[int] = mapped_column(
        ForeignKey("roles.id", name=FK_ROLE_PERMISSION_ROLE_ID),
        nullable=False,
    )
    permission_id: Mapped[int] = mapped_column(
        ForeignKey("permissions.id", name=FK_ROLE_PERMISSION_PERMISSION_ID),
        nullable=False,
    )
    effect: Mapped[PolicyEffectEnum] = mapped_column(
        Enum(PolicyEffectEnum, native_enum=False),
        nullable=False,
    )

    UQ_ROLE_PERMISSION_ROLE_PERMISSION = "uq_role_permission_role_permission"

    __table_args__ = (
        UniqueConstraint("role_id", "permission_id", name=UQ_ROLE_PERMISSION_ROLE_PERMISSION),
    )
