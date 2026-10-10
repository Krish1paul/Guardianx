"""Safe static file threat analysis API endpoints — M7.

Endpoints
---------
POST /api/v1/analyze/file          — Upload file for safe static threat analysis.
GET  /api/v1/analyze/file/history  — Paginated file scan history for authenticated user.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.models.file_scan import FileScan
from app.models.user import User
from app.schemas.unified_analysis import (
    FileScanHistoryResponse,
    FileScanResponse,
    FileScanSummary,
)
from app.schemas.url_analysis import RiskClassification
from app.services.analyzers.file_analyzer import (
    MAX_FILE_SIZE_BYTES,
    FileAnalyzer,
    FileValidationError,
)

router = APIRouter(prefix="/analyze", tags=["analyze"])

HISTORY_DEFAULT_LIMIT = 20
HISTORY_MAX_LIMIT = 100


@router.post(
    "/file",
    response_model=FileScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Safely inspect an uploaded file for threat indicators",
    description=(
        "Performs safe static inspection of uploaded files. Analyzes magic bytes, "
        "detects disguised executables, double extensions, macro-enabled documents, "
        "and evaluates archive safety without execution. "
        "Raw file contents are never permanently stored."
    ),
)
async def analyze_file(
    file: Annotated[UploadFile, File(description="File to inspect statically.")],
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> FileScanResponse:
    """Safely inspect uploaded file and return explainable risk indicators."""
    try:
        # Read file with size safety boundary
        content = await file.read(MAX_FILE_SIZE_BYTES + 1)
        if len(content) > MAX_FILE_SIZE_BYTES:
            max_mb = MAX_FILE_SIZE_BYTES // (1024 * 1024)
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"File exceeds maximum allowed upload size of {max_mb} MB.",
            )

        filename = file.filename or "uploaded_file"
        declared_mime = file.content_type

        analyzer = FileAnalyzer(db)
        return analyzer.analyze(
            input_data=(content, filename, declared_mime),
            user_id=current_user.id,
        )
    except FileValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while analyzing the file.",
        ) from None
    finally:
        await file.close()


@router.get(
    "/file/history",
    response_model=FileScanHistoryResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve file scan history",
    description="Returns the authenticated user's file scan history, newest first.",
)
def get_file_history(
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
) -> FileScanHistoryResponse:
    """Return paginated file scan records for current user."""
    try:
        count_stmt = select(func.count(FileScan.id)).where(FileScan.user_id == current_user.id)
        total = db.scalar(count_stmt) or 0

        stmt = (
            select(FileScan)
            .where(FileScan.user_id == current_user.id)
            .order_by(FileScan.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        rows = db.scalars(stmt).all()

        items = [
            FileScanSummary(
                id=r.id,
                file_hash=r.file_hash,
                filename=r.filename,
                file_size=r.file_size,
                detected_type=r.detected_type,
                risk_score=r.risk_score,
                classification=RiskClassification(r.classification),
                confidence=r.confidence,
                analyzer_version=r.analyzer_version,
                created_at=r.created_at,
            )
            for r in rows
        ]

        return FileScanHistoryResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while retrieving file scan history.",
        ) from None
