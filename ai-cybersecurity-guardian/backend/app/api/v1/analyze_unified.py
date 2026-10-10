"""Unified threat analysis dispatch API endpoint — M7.

Endpoints
---------
POST /api/v1/analyze — Unified JSON dispatch for 'url' and 'message' vectors.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.core.url_utils import URLValidationError
from app.models.user import User
from app.schemas.unified_analysis import (
    MessageScanRequest,
    MessageScanResponse,
    UnifiedScanRequest,
)
from app.schemas.url_analysis import URLScanResponse
from app.services.analyzers.message_analyzer import MessageAnalyzer
from app.services.analyzers.url_analyzer import URLAnalyzer

router = APIRouter(prefix="/analyze", tags=["analyze"])


@router.post(
    "",
    response_model=URLScanResponse | MessageScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Unified threat analysis entrypoint",
    description=(
        "Unified dispatch endpoint accepting JSON payloads for 'url' and 'message' analysis. "
        "File scanning requires multipart upload and is served at POST /api/v1/analyze/file."
    ),
)
def analyze_unified(
    body: UnifiedScanRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> Any:
    """Dispatch threat analysis based on requested input type."""
    if body.type == "url":
        if not body.url:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Field 'url' is required when analysis type is 'url'.",
            )
        try:
            return URLAnalyzer(db).analyze(input_data=body.url, user_id=current_user.id)
        except URLValidationError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=exc.detail,
            ) from exc
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred while analyzing the URL.",
            ) from None

    if body.type == "message":
        if not body.message:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Field 'message' is required when analysis type is 'message'.",
            )
        try:
            msg_req = MessageScanRequest(
                message=body.message,
                subject=body.subject,
                sender=body.sender,
            )
            return MessageAnalyzer(db).analyze(input_data=msg_req, user_id=current_user.id)
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

    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=(
            f"Unsupported analysis type '{body.type}'. Supported types: 'url', 'message'. "
            "Use POST /api/v1/analyze/file for file uploads."
        ),
    )
