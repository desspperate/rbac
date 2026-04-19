from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from rbac.constants import RBACConstants
from rbac.database import Base
from rbac.enums import ForcedTokenStatusEnum, TokenTypeEnum

if TYPE_CHECKING:
    from rbac.models import User


class Token(Base):
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(RBACConstants.HASH_LEN), unique=True, nullable=False)
    token_type: Mapped[TokenTypeEnum] = mapped_column(
        Enum(TokenTypeEnum, native_enum=False),
        nullable=False,
    )
    forced_status: Mapped[ForcedTokenStatusEnum] = mapped_column(
        Enum(ForcedTokenStatusEnum, native_enum=False),
        nullable=True,
        default=None,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    user: Mapped["User"] = relationship(
        "User",
        back_populates="tokens",
    )
