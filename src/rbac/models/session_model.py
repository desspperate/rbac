from typing import TYPE_CHECKING

from sqlalchemy import Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from rbac.constants import RBACConstants
from rbac.database import Base
from rbac.enums import ForcedSessionStatusEnum

if TYPE_CHECKING:
    from rbac.models import Token, User


class Session(Base):
    FK_SESSION_USER_ID = "fk_session_user_id"

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", name=FK_SESSION_USER_ID), nullable=False)
    forced_status: Mapped[ForcedSessionStatusEnum | None] = mapped_column(
        Enum(ForcedSessionStatusEnum, native_enum=False),
        nullable=True,
        default=None,
    )
    user_agent: Mapped[str] = mapped_column(String(RBACConstants.SESSION_USER_AGENT_MAX_LEN), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(RBACConstants.SESSION_IP_ADDRESS_MAX_LEN), nullable=False)

    user: Mapped["User"] = relationship(
        "User",
        back_populates="sessions",
    )
    tokens: Mapped[list["Token"]] = relationship(
        "Token",
        back_populates="session",
        cascade="all, delete-orphan",
    )
