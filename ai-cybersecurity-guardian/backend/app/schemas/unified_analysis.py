"""Unified multi-vector threat analysis schemas — M7.

Provides typed Pydantic models for:
- Explainable risk indicators (category, severity, title, explanation, score_contribution)
- Message threat analysis
- Safe static file analysis
- Unified multi-vector dispatch
- History pagination
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.url_analysis import RiskClassification, Severity

# ---------------------------------------------------------------------------
# Explainable Reason Schema
# ---------------------------------------------------------------------------


class ThreatCategory(str, Enum):
    """Normalized threat categories across all analyzers."""

    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"
    SUSPICIOUS_URL = "SUSPICIOUS_URL"
    FILE_ANOMALY = "FILE_ANOMALY"
    MALICIOUS_SIGNATURE = "MALICIOUS_SIGNATURE"
    ARCHIVE_RISK = "ARCHIVE_RISK"
    THREAT_INTEL = "THREAT_INTEL"
    LINGUISTIC_PRESSURE = "LINGUISTIC_PRESSURE"
    METADATA_MISMATCH = "METADATA_MISMATCH"
    REPUTATION = "REPUTATION"
    EVASION = "EVASION"
    STRUCTURAL_ANOMALY = "STRUCTURAL_ANOMALY"


class ExplainableReason(BaseModel):
    """A detailed, explainable risk indicator with category and score impact."""

    category: ThreatCategory = Field(
        ...,
        description="High-level threat category.",
        examples=["SOCIAL_ENGINEERING"],
    )
    severity: Severity = Field(
        ...,
        description="Severity level of this finding.",
        examples=["HIGH"],
    )
    title: str = Field(
        ...,
        description="Concise indicator title.",
        examples=["Credential Harvesting Trigger"],
    )
    explanation: str = Field(
        ...,
        description="Clear explanation of what was detected and why it presents risk.",
    )
    score_contribution: int = Field(
        ...,
        ge=0,
        le=100,
        description="Approximate risk points contributed by this indicator.",
    )


# ---------------------------------------------------------------------------
# Message Analyzer Schemas
# ---------------------------------------------------------------------------


class MessageScanRequest(BaseModel):
    """Payload for POST /api/v1/analyze/message."""

    message: str = Field(
        ...,
        min_length=1,
        max_length=20_000,
        description="Message or email text to analyze for phishing/social engineering.",
    )
    subject: str | None = Field(
        default=None,
        max_length=500,
        description="Optional subject line of the message.",
    )
    sender: str | None = Field(
        default=None,
        max_length=255,
        description="Optional sender address or display name.",
    )

    @model_validator(mode="before")
    @classmethod
    def _normalize_payload(cls, data: Any) -> Any:
        if isinstance(data, dict) and "message" not in data and "body" in data:
            data = dict(data)
            data["message"] = data["body"]
        return data

    @field_validator("message")
    @classmethod
    def _validate_message(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Message content cannot be empty or whitespace only.")
        return trimmed


class ExtractedURLAnalysis(BaseModel):
    """Analysis summary of a URL discovered inside a message."""

    url: str
    risk_score: int
    classification: RiskClassification


class MessageScanResponse(BaseModel):
    """Response returned by POST /api/v1/analyze/message."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID = Field(..., description="Unique scan identifier.")
    message_hash: str = Field(..., description="SHA-256 digest of the message.")
    risk_score: int = Field(..., ge=0, le=100, description="Overall risk score in [0, 100].")
    classification: RiskClassification = Field(..., description="Derived risk tier.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Model/engine confidence in [0, 1].")
    reasons: list[ExplainableReason] = Field(
        default_factory=list, description="Explainable findings."
    )
    features: dict[str, Any] = Field(default_factory=dict, description="Extracted feature metrics.")
    extracted_urls: list[ExtractedURLAnalysis] = Field(
        default_factory=list, description="URLs identified in message and their risk assessment."
    )
    analyzer_version: str = Field(..., description="Analyzer engine version.")
    created_at: datetime = Field(..., description="UTC scan timestamp.")


class MessageScanSummary(BaseModel):
    """Summary item for message scan history."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    message_hash: str
    subject: str | None = None
    risk_score: int
    classification: RiskClassification
    confidence: float
    analyzer_version: str
    created_at: datetime


class MessageScanHistoryResponse(BaseModel):
    """Paginated message scan history."""

    items: list[MessageScanSummary]
    total: int
    limit: int
    offset: int


# ---------------------------------------------------------------------------
# File Analyzer Schemas
# ---------------------------------------------------------------------------


class FileScanResponse(BaseModel):
    """Response returned by POST /api/v1/analyze/file."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID = Field(..., description="Unique scan identifier.")
    file_hash: str = Field(..., description="SHA-256 digest of the file content.")
    filename: str = Field(..., description="Sanitized original filename.")
    file_size: int = Field(..., ge=0, description="File size in bytes.")
    detected_type: str = Field(..., description="File signature detected via magic bytes.")
    declared_mime: str = Field(..., description="Declared or inferred MIME type.")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score in [0, 100].")
    classification: RiskClassification = Field(..., description="Derived risk classification tier.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence.")
    reasons: list[ExplainableReason] = Field(
        default_factory=list, description="Explainable reasons."
    )
    features: dict[str, Any] = Field(default_factory=dict, description="Static feature breakdown.")
    analyzer_version: str = Field(..., description="Analyzer engine version.")
    created_at: datetime = Field(..., description="UTC scan timestamp.")


class FileScanSummary(BaseModel):
    """Summary item for file scan history."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    file_hash: str
    filename: str
    file_size: int
    detected_type: str
    risk_score: int
    classification: RiskClassification
    confidence: float
    analyzer_version: str
    created_at: datetime


class FileScanHistoryResponse(BaseModel):
    """Paginated file scan history."""

    items: list[FileScanSummary]
    total: int
    limit: int
    offset: int


# ---------------------------------------------------------------------------
# Unified Analyzer Schemas (URL & Message via JSON)
# ---------------------------------------------------------------------------


class UnifiedScanRequest(BaseModel):
    """Request body for POST /api/v1/analyze.

    Supports JSON dispatch for 'url' and 'message'.
    Note: File uploads must use POST /api/v1/analyze/file with multipart/form-data.
    """

    type: Literal["url", "message"] = Field(
        ...,
        description=(
            "Target analysis type: 'url' or 'message'. "
            "File scanning uses POST /api/v1/analyze/file."
        ),
    )
    url: str | None = Field(
        default=None,
        description="Required if type is 'url'. The target URL string.",
    )
    message: str | None = Field(
        default=None,
        description="Required if type is 'message'. Message or email text.",
    )
    subject: str | None = Field(
        default=None,
        description="Optional subject line when type is 'message'.",
    )
    sender: str | None = Field(
        default=None,
        description="Optional sender identifier when type is 'message'.",
    )

    @field_validator("url")
    @classmethod
    def _validate_url_when_present(cls, v: str | None) -> str | None:
        if v is not None and not v.strip():
            raise ValueError("URL cannot be blank when provided.")
        return v
