"""Health, liveness, and readiness check endpoints — M0 & M5.

Endpoints
---------
GET /health        — Baseline service health (M0 contract: {"status": "ok"}).
GET /health/live   — Liveness probe: returns 200 without dependency checks.
GET /health/ready  — Readiness probe: verifies DB connectivity and Redis status.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.config import get_settings
from app.core.redis import RedisClientProtocol, get_redis_client
from app.schemas.health import HealthResponse, LivenessResponse, ReadinessResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service health status",
)
def health_check() -> HealthResponse:
    """Return baseline service health.

    Contract preserved from M0 for backward compatibility.
    """
    return HealthResponse(status="ok")


@router.get(
    "/health/live",
    response_model=LivenessResponse,
    summary="Liveness probe",
)
def liveness_check() -> LivenessResponse:
    """Kubernetes / container liveness probe.

    Returns 200 OK immediately without querying downstream dependencies.
    """
    return LivenessResponse(status="alive")


@router.get(
    "/health/ready",
    response_model=ReadinessResponse,
    summary="Readiness probe",
)
def readiness_check(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    redis_client: Annotated[RedisClientProtocol, Depends(get_redis_client)],
) -> ReadinessResponse:
    """Kubernetes / orchestrator readiness probe.

    Checks:
      1. PostgreSQL database connectivity via `SELECT 1`.
      2. Redis connectivity via ping (if enabled).

    Returns:
      - HTTP 200 with status="ready" if all required dependencies are healthy.
      - HTTP 503 with status="unhealthy" if any required dependency fails.
      Internal credentials, connection strings, or error traces are NEVER exposed.
    """
    settings = get_settings()
    is_ready = True

    # 1. Database check
    db_status = "healthy"
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        logger.warning("Readiness probe DB check failed: %s", exc)
        db_status = "unhealthy"
        is_ready = False

    # 2. Redis check
    if settings.redis_enabled:
        try:
            if redis_client.ping():
                redis_status = "healthy"
            else:
                redis_status = "unhealthy"
                is_ready = False
        except Exception as exc:
            logger.warning("Readiness probe Redis check failed: %s", exc)
            redis_status = "unhealthy"
            is_ready = False
    else:
        redis_status = "disabled"

    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return ReadinessResponse(
            status="unhealthy",
            database=db_status,
            redis=redis_status,
        )

    return ReadinessResponse(
        status="ready",
        database=db_status,
        redis=redis_status,
    )
