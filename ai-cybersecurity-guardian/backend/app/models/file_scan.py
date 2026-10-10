"""FileScan ORM model — M7.

Safety & Privacy decisions:
- File contents are NEVER stored permanently in the database or filesystem.
- Uploaded files are evaluated in-memory / safe temporary storage and immediately cleaned up.
- ``file_hash`` stores the SHA-256 digest for audit and reputation checks.
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


class FileScan(Base):
    """Persisted result of a safe static file threat analysis."""

    __tablename__ = "file_scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # SHA-256 hex digest (64 chars) of file content.
    file_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    detected_type: Mapped[str] = mapped_column(String(64), nullable=False)
    declared_mime: Mapped[str] = mapped_column(String(128), nullable=False)

    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    classification: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[float] = mapped_column(nullable=False, default=1.0)

    # JSONB on PostgreSQL, JSON on SQLite (for tests)
    features: Mapped[Any] = mapped_column(JSONB().with_variant(JSON(), "sqlite"), nullable=False)
    reasons: Mapped[Any] = mapped_column(JSONB().with_variant(JSON(), "sqlite"), nullable=False)

    analyzer_version: Mapped[str] = mapped_column(String(32), nullable=False, default="file-v1")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    user: Mapped[Any] = relationship("User", back_populates="file_scans")

    def __repr__(self) -> str:
        return (
            f"<FileScan id={self.id} user_id={self.user_id} "
            f"score={self.risk_score} classification={self.classification}>"
        )
