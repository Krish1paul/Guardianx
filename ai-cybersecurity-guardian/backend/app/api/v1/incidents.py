"""Incidents API router — M8.

Endpoints:
- GET   /api/v1/incidents                  (paginated list, filterable by status/severity/search)
- GET   /api/v1/incidents/{incident_id}    (detailed incident view)
- PATCH /api/v1/incidents/{incident_id}/status (status transition)
- GET   /api/v1/incidents/{incident_id}/timeline (chronological real-event timeline)

Strict tenant isolation is enforced: users can only see and modify their own incidents.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.models.file_scan import FileScan
from app.models.incident import Incident, IncidentEvent
from app.models.message_scan import MessageScan
from app.models.url_scan import URLScan
from app.models.user import User
from app.schemas.incident import (
    IncidentDetailResponse,
    IncidentListResponse,
    IncidentStatus,
    IncidentStatusUpdateRequest,
    IncidentSummaryResponse,
    IncidentTimelineEvent,
    IncidentTimelineResponse,
)

router = APIRouter(prefix="/incidents", tags=["Incidents & Security Intelligence"])


@router.get(
    "",
    response_model=IncidentListResponse,
    status_code=status.HTTP_200_OK,
    summary="List security incidents for the authenticated user",
)
def list_incidents(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    incident_status: Annotated[
        IncidentStatus | None,
        Query(alias="status", description="Filter by lifecycle status."),
    ] = None,
    severity: Annotated[
        str | None,
        Query(description="Filter by severity tier (LOW, MEDIUM, HIGH, CRITICAL)."),
    ] = None,
    search: Annotated[
        str | None,
        Query(description="Search term matching title or indicator."),
    ] = None,
    limit: Annotated[
        int,
        Query(ge=1, le=100, description="Page size limit."),
    ] = 20,
    offset: Annotated[
        int,
        Query(ge=0, description="Offset cursor for pagination."),
    ] = 0,
) -> IncidentListResponse:
    """Retrieve paginated incidents belonging to the authenticated user."""
    base_query = select(Incident).where(Incident.user_id == current_user.id)

    if incident_status:
        base_query = base_query.where(Incident.status == incident_status.value)
    if severity:
        base_query = base_query.where(Incident.severity == severity.upper())
    if search:
        search_term = f"%{search.strip()}%"
        base_query = base_query.where(Incident.title.ilike(search_term))

    # Total count
    count_query = select(func.count()).select_from(base_query.subquery())
    total = db.scalar(count_query) or 0

    # Paginated results ordered by last_seen descending
    items_query = base_query.order_by(Incident.last_seen.desc()).limit(limit).offset(offset)
    items = list(db.scalars(items_query).all())

    return IncidentListResponse(
        items=[IncidentSummaryResponse.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{incident_id}",
    response_model=IncidentDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get details of a specific security incident",
)
def get_incident(
    incident_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> IncidentDetailResponse:
    """Retrieve full incident details including reasons and indicators."""
    incident = db.scalar(
        select(Incident).where(
            Incident.id == incident_id,
            Incident.user_id == current_user.id,
        )
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found.",
        )

    return IncidentDetailResponse.model_validate(incident)


@router.patch(
    "/{incident_id}/status",
    response_model=IncidentDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Update the lifecycle status of an incident",
)
def update_incident_status(
    incident_id: uuid.UUID,
    payload: IncidentStatusUpdateRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> IncidentDetailResponse:
    """Update incident status (OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE)."""
    incident = db.scalar(
        select(Incident).where(
            Incident.id == incident_id,
            Incident.user_id == current_user.id,
        )
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found.",
        )

    incident.status = payload.status.value
    db.commit()
    db.refresh(incident)

    return IncidentDetailResponse.model_validate(incident)


@router.get(
    "/{incident_id}/timeline",
    response_model=IncidentTimelineResponse,
    status_code=status.HTTP_200_OK,
    summary="Get the chronological event timeline for an incident",
)
def get_incident_timeline(
    incident_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> IncidentTimelineResponse:
    """Retrieve chronological event timeline with resolved scan metadata."""
    incident = db.scalar(
        select(Incident).where(
            Incident.id == incident_id,
            Incident.user_id == current_user.id,
        )
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found.",
        )

    # Fetch events ordered by creation time
    events_stmt = (
        select(IncidentEvent)
        .where(IncidentEvent.incident_id == incident.id)
        .order_by(IncidentEvent.created_at.asc())
    )
    events = list(db.scalars(events_stmt).all())

    timeline_items: list[IncidentTimelineEvent] = []
    for ev in events:
        summary_label: str | None = None
        risk_score: int | None = None
        classification: str | None = None

        if ev.event_type == "url_scan":
            scan = db.scalar(select(URLScan).where(URLScan.id == ev.event_id))
            if scan:
                summary_label = scan.normalized_url
                risk_score = scan.risk_score
                classification = scan.classification
        elif ev.event_type == "message_scan":
            m_scan = db.scalar(select(MessageScan).where(MessageScan.id == ev.event_id))
            if m_scan:
                summary_label = m_scan.subject or "Message / Text Content"
                risk_score = m_scan.risk_score
                classification = m_scan.classification
        elif ev.event_type == "file_scan":
            f_scan = db.scalar(select(FileScan).where(FileScan.id == ev.event_id))
            if f_scan:
                summary_label = f"File: {f_scan.filename}"
                risk_score = f_scan.risk_score
                classification = f_scan.classification

        timeline_items.append(
            IncidentTimelineEvent(
                id=ev.id,
                event_type=ev.event_type,
                event_id=ev.event_id,
                relationship_reason=ev.relationship_reason,
                created_at=ev.created_at,
                summary=summary_label,
                risk_score=risk_score,
                classification=classification,
            )
        )

    return IncidentTimelineResponse(
        incident_id=incident.id,
        title=incident.title,
        severity=incident.severity,
        status=incident.status,
        events=timeline_items,
    )
