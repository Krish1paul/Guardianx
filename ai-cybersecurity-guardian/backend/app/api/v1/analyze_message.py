"""Message threat analysis API endpoints — M7.

Endpoints
---------
POST /api/v1/analyze/message          — Analyze text/message for phishing & social engineering.
GET  /api/v1/analyze/message/history  — Paginated message scan history for authenticated user.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.models.message_scan import MessageScan
from app.models.user import User
from app.schemas.unified_analysis import (
    MessageScanHistoryResponse,
    MessageScanRequest,
    MessageScanResponse,
    MessageScanSummary,
)
from app.schemas.url_analysis import RiskClassification
from app.services.analyzers.message_analyzer import MessageAnalyzer

router = APIRouter(prefix="/analyze", tags=["analyze"])

HISTORY_DEFAULT_LIMIT = 20
HISTORY_MAX_LIMIT = 100


@router.post(
    "/message",
    response_model=MessageScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze text/message for phishing and social engineering",
    description=(
        "Evaluates message text for social engineering patterns (urgency, credential harvesting, "
        "financial solicitation, impersonation), extracts and assesses embedded URLs, "
        "and applies a trained ML classifier. Raw message content is never permanently stored."
    ),
)
def analyze_message(
    body: MessageScanRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> MessageScanResponse:
    """Analyze a message and return explainable risk indicators."""
    try:
        analyzer = MessageAnalyzer(db)
        return analyzer.analyze(input_data=body, user_id=current_user.id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while analyzing the message.",
        ) from None


@router.get(
    "/message/history",
    response_model=MessageScanHistoryResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve message scan history",
    description="Returns the authenticated user's message scan history, newest first.",
)
def get_message_history(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    limit: Annotated[
        int,
        Query(ge=1, le=HISTORY_MAX_LIMIT, description="Maximum items per page."),
    ] = HISTORY_DEFAULT_LIMIT,
    offset: Annotated[
        int,
        Query(ge=0, description="Pagination offset."),
    ] = 0,
) -> MessageScanHistoryResponse:
    """Return paginated message scan records for current user."""
    try:
        count_stmt = select(func.count(MessageScan.id)).where(
            MessageScan.user_id == current_user.id
        )
        total = db.scalar(count_stmt) or 0

        stmt = (
            select(MessageScan)
            .where(MessageScan.user_id == current_user.id)
            .order_by(MessageScan.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        rows = db.scalars(stmt).all()

        items = [
            MessageScanSummary(
                id=r.id,
                message_hash=r.message_hash,
                subject=r.subject,
                risk_score=r.risk_score,
                classification=RiskClassification(r.classification),
                confidence=r.confidence,
                analyzer_version=r.analyzer_version,
                created_at=r.created_at,
            )
            for r in rows
        ]

        return MessageScanHistoryResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while retrieving message scan history.",
        ) from None
