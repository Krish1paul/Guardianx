"""Aggregates all v1 API routers."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.analyze_file import router as analyze_file_router
from app.api.v1.analyze_message import router as analyze_message_router
from app.api.v1.analyze_unified import router as analyze_unified_router
from app.api.v1.analyze_url import router as analyze_url_router
from app.api.v1.auth import router as auth_router
from app.api.v1.health import router as health_router
from app.api.v1.incidents import router as incidents_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(analyze_url_router)
api_router.include_router(analyze_message_router)
api_router.include_router(analyze_file_router)
api_router.include_router(analyze_unified_router)
api_router.include_router(incidents_router)
