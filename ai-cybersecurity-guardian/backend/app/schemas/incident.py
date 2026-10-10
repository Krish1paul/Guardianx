"""Incident schemas — M8.

Pydantic models for Security Incident listing, details, timeline, and status updates.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class IncidentStatus(str, Enum):
    """Lifecycle status of a security incident."""

    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class AttackStage(str, Enum):
    """Categorized attack chain stage."""

    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"
    PHISHING = "PHISHING"
    CREDENTIAL_HARVESTING = "CREDENTIAL_HARVESTING"
    MALICIOUS_LINK = "MALICIOUS_LINK"
    SUSPICIOUS_ATTACHMENT = "SUSPICIOUS_ATTACHMENT"
    MULTI_VECTOR_CAMPAIGN = "MULTI_VECTOR_CAMPAIGN"
    REPEATED_THREAT = "REPEATED_THREAT"


class IncidentSummaryResponse(BaseModel):
    """Summary item for incident list views."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    severity: str
    risk_score: int
    confidence: float
    status: str
    attack_stage: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    indicators: list[dict[str, Any]]
    created_at: datetime


class IncidentDetailResponse(BaseModel):
    """Detailed response for an individual incident entity."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    severity: str
    risk_score: int
    confidence: float
    status: str
    attack_stage: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    indicators: list[dict[str, Any]]
    reasons: list[dict[str, Any]]
    created_at: datetime
    updated_at: datetime


class IncidentListResponse(BaseModel):
    """Paginated collection of security incidents."""

    items: list[IncidentSummaryResponse]
    total: int
    limit: int
    offset: int


class IncidentStatusUpdateRequest(BaseModel):
    """Payload to update an incident's lifecycle status."""

    status: IncidentStatus = Field(..., description="Target lifecycle status.")


class IncidentTimelineEvent(BaseModel):
    """Chronological event element within an incident timeline."""

    id: uuid.UUID
    event_type: str
    event_id: uuid.UUID
    relationship_reason: str
    created_at: datetime
    summary: str | None = None
    risk_score: int | None = None
    classification: str | None = None


class IncidentTimelineResponse(BaseModel):
    """Complete chronological timeline of an incident."""

    incident_id: uuid.UUID
    title: str
    severity: str
    status: str
    events: list[IncidentTimelineEvent]
