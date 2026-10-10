"""MessageScan ORM model — M7.

Privacy decisions:
- The raw message body is NEVER stored in the database.
- ``message_hash`` stores the SHA-256 digest of the message content for lookup and deduplication.
- Only non-sensitive metadata (optional subject, sanitized sender, scores, reasons,
  and extracted metrics) is persisted.
- Rows are strictly isolated per user (WHERE user_id = current_user.id).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.db.base import Base


class MessageScan(Base):
    """Persisted result of a message/text threat analysis."""

    __tablename__ = "message_scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # SHA-256 hex digest (64 chars) of message body.
    message_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Optional metadata (never stores full body)
    subject: Mapped[str | None] = mapped_column(String(500), nullable=True)
    sender: Mapped[str | None] = mapped_column(String(255), nullable=True)

    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    classification: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[float] = mapped_column(nullable=False, default=1.0)

    # JSONB on PostgreSQL, JSON on SQLite (for tests)
    features: Mapped[Any] = mapped_column(JSONB().with_variant(JSON(), "sqlite"), nullable=False)
    reasons: Mapped[Any] = mapped_column(JSONB().with_variant(JSON(), "sqlite"), nullable=False)
    extracted_urls: Mapped[Any] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False
    )

    analyzer_version: Mapped[str] = mapped_column(String(32), nullable=False, default="message-v1")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    user: Mapped[Any] = relationship("User", back_populates="message_scans")

    def __repr__(self) -> str:
        return (
            f"<MessageScan id={self.id} user_id={self.user_id} "
            f"score={self.risk_score} classification={self.classification}>"
        )
