"""Incident and IncidentEvent ORM models — M8.

Provides normalized models for Security Incidents and their associated
security events (URL scans, message scans, file scans, threat intelligence).

Security & Privacy decisions:
- Rows are strictly isolated per user (WHERE user_id = current_user.id).
- Raw sensitive content is never stored; only normalized indicator references
  and explainable security reasons are recorded.
- Event associations store references (event_id, event_type) rather than
  duplicating entire scan payloads.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.user import User


class Incident(Base):
    """Correlated security incident aggregating multiple threat signals."""

    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="LOW", index=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)

    # Status: OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="OPEN", index=True)

    # Attack Stage: SOCIAL_ENGINEERING, PHISHING, CREDENTIAL_HARVESTING,
    # MALICIOUS_LINK, SUSPICIOUS_ATTACHMENT, MULTI_VECTOR_CAMPAIGN, REPEATED_THREAT
    attack_stage: Mapped[str] = mapped_column(String(50), nullable=False, default="REPEATED_THREAT")

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # JSONB on PostgreSQL, JSON on SQLite (for tests)
    # List of normalized indicator dicts: [{"type": "domain", "value": "paypa1.com"}]
    indicators: Mapped[Any] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=list
    )

    # List of ExplainableReason dicts
    reasons: Mapped[Any] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=list
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    user: Mapped[User] = relationship("User", back_populates="incidents")
    events: Mapped[list[IncidentEvent]] = relationship(
        "IncidentEvent",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentEvent.created_at",
    )

    def __repr__(self) -> str:
        return (
            f"<Incident id={self.id} user_id={self.user_id} "
            f"severity={self.severity} status={self.status}>"
        )


class IncidentEvent(Base):
    """Association linking an Incident to a specific threat scan or detection event."""

    __tablename__ = "incident_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Event types: "url_scan", "message_scan", "file_scan", "threat_intel"
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)

    # Referenced scan record id
    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)

    # Explainable relationship explanation: e.g. "Matching suspicious domain 'paypa1.com'"
    relationship_reason: Mapped[str] = mapped_column(String(255), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    incident: Mapped[Incident] = relationship("Incident", back_populates="events")

    def __repr__(self) -> str:
        return (
            f"<IncidentEvent id={self.id} incident_id={self.incident_id} "
            f"type={self.event_type} event_id={self.event_id}>"
        )
