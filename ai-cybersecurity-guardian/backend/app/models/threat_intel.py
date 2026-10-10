"""ThreatIntelligenceResult ORM model — M4.

One row is created per URL scan when threat-intelligence enrichment is performed.
If TI is disabled or the kill-switch is off, no row is created.

Design
------
-  Separate table — existing ``url_scans`` rows are NEVER modified.
-  FK to ``url_scans.id`` with ON DELETE CASCADE so rows are cleaned up
   automatically when a scan is deleted.
-  ``status`` stores the ThreatIntelStatus enum value as a string.
-  ``provider_error`` records whether the provider call failed so historical
   data distinguishes "no data" from "call failed".
-  ``cached`` records whether the result was served from the in-memory cache.

Privacy
-------
Only the reputation verdict is stored here, not the raw URL.
The URL can be retrieved from the parent ``url_scans`` row.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class ThreatIntelligenceResult(Base):
    """Persisted threat-intelligence enrichment for a URL scan."""

    __tablename__ = "threat_intelligence_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # FK to the parent URLScan row.  Cascade-deletes when the scan is removed.
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("url_scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        unique=True,  # One TI result per scan
    )

    # e.g. "virustotal", "mock"
    provider: Mapped[str] = mapped_column(String(64), nullable=False)

    # "CLEAN", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"
    status: Mapped[str] = mapped_column(String(20), nullable=False)

    # Normalised confidence [0, 1]; NULL if provider did not report one.
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Human-readable reason from the provider; NULL if not available.
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # True when this result was served from the in-memory cache.
    cached: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # True when the provider call failed (timeout, network error, etc.).
    provider_error: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # UTC timestamp when the TI query was performed.
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationship back to URLScan (no cascade — only FK cascade applies).
    url_scan: Mapped[Any] = relationship("URLScan", back_populates="threat_intel")

    def __repr__(self) -> str:
        return (
            f"<ThreatIntelligenceResult id={self.id} scan_id={self.scan_id} "
            f"provider={self.provider!r} status={self.status}>"
        )
