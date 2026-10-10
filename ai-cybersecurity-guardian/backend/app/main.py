"""FastAPI application entrypoint — M0 Foundation & M5 Production Hardening."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.health import router as health_router
from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.middleware.body_size_limit import BodySizeLimitMiddleware
from app.middleware.correlation_id import CorrelationIdMiddleware, get_correlation_id
from app.middleware.security_headers import SecurityHeadersMiddleware

settings = get_settings()
configure_logging(settings.environment)
logger = get_logger(__name__)


def create_app() -> FastAPI:
    settings.validate_production_secrets()

    app = FastAPI(
        title="Guardianx",
        description="Privacy-first personal cybersecurity risk platform.",
        version="0.1.0",
    )

    # -----------------------------------------------------------------------
    # Centralized Unhandled Exception Handler (No internal leaks)
    # -----------------------------------------------------------------------
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        cid = get_correlation_id()
        logger.exception("Unhandled exception [correlation_id=%s]: %s", cid, exc)
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Internal server error.",
                "correlation_id": cid,
            },
        )

    # -----------------------------------------------------------------------
    # Middleware Stack
    # (Execution order: CorrelationId -> TrustedHost -> SecurityHeaders -> BodySize -> CORS)
    # -----------------------------------------------------------------------
    app.add_middleware(CorrelationIdMiddleware)

    if settings.allowed_hosts_list and settings.allowed_hosts_list != ["*"]:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.allowed_hosts_list,
        )

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-Correlation-ID"],
    )

    # -----------------------------------------------------------------------
    # Routers
    # -----------------------------------------------------------------------
    app.include_router(api_router, prefix="/api/v1")
    # Also expose /health, /health/live, /health/ready unprefixed for Docker/k8s
    app.include_router(health_router)

    logger.info("Application configured for environment=%s", settings.environment)
    return app


app = create_app()
