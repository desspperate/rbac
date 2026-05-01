from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from rbac.constants import RBACConstants
from rbac.database import Base
from rbac.enums import ForcedTokenStatusEnum, TokenTypeEnum

if TYPE_CHECKING:
    from rbac.models import Session


class Token(Base):
    FK_TOKEN_SESSION_ID = "fk_token_session_id"  # noqa: S105
    UQ_TOKEN_TOKEN_HASH = "uq_token_token_hash"  # noqa: S105
    UQ_TOKEN_ACTIVE_PER_SESSION_TYPE = "uq_token_active_per_session_type"  # noqa: S105

    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id", name=FK_TOKEN_SESSION_ID), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(RBACConstants.HASH_MAX_LEN), nullable=False)
    token_type: Mapped[TokenTypeEnum] = mapped_column(
        Enum(TokenTypeEnum, native_enum=False),
        nullable=False,
    )
    forced_status: Mapped[ForcedTokenStatusEnum | None] = mapped_column(
        Enum(ForcedTokenStatusEnum, native_enum=False),
        nullable=True,
        default=None,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    session: Mapped["Session"] = relationship(
        "Session",
        back_populates="tokens",
    )

    __table_args__ = (
        UniqueConstraint("token_hash", name=UQ_TOKEN_TOKEN_HASH),
        Index(
            UQ_TOKEN_ACTIVE_PER_SESSION_TYPE,
            "session_id",
            "token_type",
            unique=True,
            postgresql_where=text("forced_status IS NULL"),
        ),
    )
