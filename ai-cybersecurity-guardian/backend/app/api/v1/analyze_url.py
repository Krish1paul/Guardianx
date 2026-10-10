"""URL threat analysis API endpoints — M2.

Endpoints
---------
POST  /api/v1/analyze/url          — Analyze a URL; returns full risk result.
GET   /api/v1/analyze/url/history  — Paginated scan history for authenticated user.

Authentication
--------------
Both endpoints require a valid Bearer access token.
``get_current_user`` is used as a FastAPI dependency (M1).

Authorization
-------------
- URL scans are associated with the authenticated user automatically.
- History only returns scans belonging to the authenticated user.
- ``user_id`` is NEVER read from the request body or query parameters.

SSRF safety
-----------
The analyzer is a static string parser.  No network requests are made to
the submitted URL.  See ``app/services/url_analyzer.py`` and
``ml/features/url_features.py`` for details.

Error handling
--------------
- Invalid URL → 422 Unprocessable Entity with a descriptive message.
- Unauthenticated → 401 Unauthorized.
- Database errors → 500 Internal Server Error (no internal details exposed).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.core.url_utils import URLValidationError
from app.models.user import User
from app.schemas.url_analysis import (
    URLScanHistoryResponse,
    URLScanRequest,
    URLScanResponse,
)
from app.services.url_analyzer import (
    HISTORY_DEFAULT_LIMIT,
    HISTORY_MAX_LIMIT,
    URLAnalyzerService,
)

router = APIRouter(prefix="/analyze", tags=["analyze"])


def _svc(db: Session) -> URLAnalyzerService:
    return URLAnalyzerService(db)


# ---------------------------------------------------------------------------
# POST /analyze/url — Submit URL for analysis
# ---------------------------------------------------------------------------


@router.post(
    "/url",
    response_model=URLScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze a URL for threat indicators",
    description=(
        "Submits a URL for deterministic, static threat analysis.  "
        "The analyzer extracts structural, lexical, and security features "
        "from the URL string and applies a weighted rule engine to produce "
        "a risk score (0–100) with explainable reasons.  "
        "**No network request is made to the submitted URL.**  "
        "Results are persisted and accessible via the history endpoint."
    ),
)
def analyze_url(
    body: URLScanRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> URLScanResponse:
    """Analyze a URL and return a structured threat assessment.

    - Validates the URL (scheme, format, length, control characters).
    - Normalizes the URL to a canonical form.
    - Extracts structural, host, security, and lexical features.
    - Scores risk via a deterministic, explainable rule engine.
    - Persists the result linked to the authenticated user.
    - Returns the full analysis result.

    The submitted URL is never fetched, crawled, or resolved.
    """
    try:
        return _svc(db).analyze(url=body.url, user_id=current_user.id)
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


# ---------------------------------------------------------------------------
# GET /analyze/url/history — Retrieve scan history
# ---------------------------------------------------------------------------


@router.get(
    "/url/history",
    response_model=URLScanHistoryResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve URL scan history",
    description=(
        "Returns the authenticated user's URL scan history, newest first.  "
        "Supports pagination via ``limit`` and ``offset``.  "
        "Users can only access their own scan history."
    ),
)
def get_url_history(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=HISTORY_MAX_LIMIT,
            description=f"Maximum items per page (1–{HISTORY_MAX_LIMIT}).",
        ),
    ] = HISTORY_DEFAULT_LIMIT,
    offset: Annotated[
        int,
        Query(ge=0, description="Pagination offset."),
    ] = 0,
) -> URLScanHistoryResponse:
    """Return the authenticated user's URL scan history.

    Authorization is enforced at the database query level:
    only scans belonging to ``current_user.id`` are returned.
    """
    try:
        return _svc(db).get_history(
            user_id=current_user.id,
            limit=limit,
            offset=offset,
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while retrieving scan history.",
        ) from None
