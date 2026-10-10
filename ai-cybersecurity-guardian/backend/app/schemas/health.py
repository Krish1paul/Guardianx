from __future__ import annotations

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str


class LivenessResponse(BaseModel):
    status: str


class ReadinessResponse(BaseModel):
    status: str
    database: str
    redis: str
