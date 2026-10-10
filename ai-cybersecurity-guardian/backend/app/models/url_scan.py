"""URLScan ORM model — M2/M4.

Privacy decision
----------------
``normalized_url`` is stored in plaintext.  This is a deliberate, documented
decision: the field is required to display scan history to the user in a
meaningful way (users cannot identify past scans from a hash alone).

Mitigations:
- Only the authenticated owner can read their scans (enforced in the service
  and query layers via ``WHERE user_id = current_user.id``).
- Users are advised not to submit URLs containing sensitive tokens or PII
  in query strings.
- A future M5 privacy control may add configurable URL redaction.

``url_hash`` stores the SHA-256 digest of the normalized URL and is used for
deduplication queries and efficient lookup without exposing the URL plaintext
in index structures.

Analyzer versioning
-------------------
``analyzer_version`` is set at scan time and never overwritten.  M3 will
insert rows with ``analyzer_version = "ml-v1"``.  Historical M2 rows retain
``"rule-v1"`` so that result provenance is always clear.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.db.base import Base


class URLScan(Base):
    """Persisted result of a URL threat analysis.

    Each row belongs to exactly one user and is never shared across users.
    """

    __tablename__ = "url_scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # SHA-256 hex digest (64 chars) of the normalized URL.
    # Used for deduplication / lookup without exposing URL in indexes.
    url_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Stored plaintext for UX — see privacy decision above.
    normalized_url: Mapped[str] = mapped_column(Text, nullable=False)

    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)

    # e.g. "LOW_RISK", "MEDIUM_RISK", "HIGH_RISK", "CRITICAL"
    classification: Mapped[str] = mapped_column(String(20), nullable=False)

    # JSONB on PostgreSQL, JSON on SQLite (for tests).
    # Stores the full URLFeatures dict.
    features: Mapped[Any] = mapped_column(JSONB().with_variant(JSON(), "sqlite"), nullable=False)

    # List of RiskReason dicts.
    reasons: Mapped[Any] = mapped_column(JSONB().with_variant(JSON(), "sqlite"), nullable=False)

    # "rule-v1" for M2; "ml-v1" for M3.
    analyzer_version: Mapped[str] = mapped_column(String(32), nullable=False, default="rule-v1")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationship back to User (no cascade on User side — scans cascade
    # DELETE when the user is deleted, see ForeignKey ondelete="CASCADE").
    user: Mapped[Any] = relationship("User", back_populates="url_scans")

    # M4: optional one-to-one TI result (may be None if TI was not performed).
    threat_intel: Mapped[Any] = relationship(
        "ThreatIntelligenceResult",
        back_populates="url_scan",
        uselist=False,
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return (
            f"<URLScan id={self.id} user_id={self.user_id} "
            f"score={self.risk_score} classification={self.classification}>"
        )
