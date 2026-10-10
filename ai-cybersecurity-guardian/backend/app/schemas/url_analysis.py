"""URL analysis request/response schemas — M2/M3/M4.

Schema hierarchy
----------------
Request:
    URLScanRequest          ← validated inbound URL

Response (full scan):
    URLScanResponse         ← returned by POST /api/v1/analyze/url

Response (history list):
    URLScanSummary          ← one item in the history list
    URLScanHistoryResponse  ← paginated wrapper

Supporting types:
    RiskClassification      ← enum (LOW_RISK … CRITICAL)
    Severity                ← enum (LOW … CRITICAL)
    ReasonCode              ← enum (IP_HOSTNAME, PUNYCODE_DOMAIN, … TI_REPUTATION)
    RiskReason              ← single explainable reason
    ThreatIntelStatus       ← enum (M4)
    ThreatIntelSummary      ← TI enrichment result embedded in response (M4)

Security:
    - URL is validated at both schema level (Pydantic) and application level
      (``app.core.url_utils.validate_url``).
    - ``classification`` is NEVER accepted from the caller; it is derived from
      the risk score server-side.
    - ``user_id`` is NEVER accepted from the caller; it is read from the
      authenticated session.
    - Internal implementation details (ORM IDs, raw DB fields) are not exposed.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.url_utils import MAX_URL_LENGTH, URLValidationError, validate_url

# ---------------------------------------------------------------------------
# Supporting enums (mirrors ml.features.url_risk_engine for API stability)
# ---------------------------------------------------------------------------


class RiskClassification(str, Enum):
    """Risk tier derived from the numeric score."""

    LOW_RISK = "LOW_RISK"
    MEDIUM_RISK = "MEDIUM_RISK"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"


class Severity(str, Enum):
    """Severity of an individual risk reason."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ReasonCode(str, Enum):
    """Machine-readable reason codes for risk explanations."""

    HTTP_NOT_HTTPS = "HTTP_NOT_HTTPS"
    IP_HOSTNAME = "IP_HOSTNAME"
    PUNYCODE_DOMAIN = "PUNYCODE_DOMAIN"
    EXCESSIVE_SUBDOMAINS = "EXCESSIVE_SUBDOMAINS"
    SUSPICIOUS_TLD = "SUSPICIOUS_TLD"
    SUSPICIOUS_KEYWORD = "SUSPICIOUS_KEYWORD"
    CREDENTIAL_PATH = "CREDENTIAL_PATH"
    USERINFO_PRESENT = "USERINFO_PRESENT"
    NON_STANDARD_PORT = "NON_STANDARD_PORT"
    EXCESSIVE_URL_LENGTH = "EXCESSIVE_URL_LENGTH"
    HIGH_ENCODING_RATIO = "HIGH_ENCODING_RATIO"
    SUSPICIOUS_COMBINATION = "SUSPICIOUS_COMBINATION"
    # M4 — Threat Intelligence
    TI_REPUTATION = "TI_REPUTATION"


# ---------------------------------------------------------------------------
# M4 — Threat Intelligence types
# ---------------------------------------------------------------------------


class ThreatIntelStatus(str, Enum):
    """Status returned by a threat-intelligence provider."""

    CLEAN = "CLEAN"  # provider found URL and rated it clean
    SUSPICIOUS = "SUSPICIOUS"  # provider flagged URL as suspicious
    MALICIOUS = "MALICIOUS"  # provider flagged URL as malicious
    UNKNOWN = "UNKNOWN"  # provider had no data for this URL


class ThreatIntelSummary(BaseModel):
    """Summary of a threat-intelligence enrichment result.

    Embedded as an optional field in URLScanResponse.
    Not present for historical M0-M3 scans.
    """

    provider: str = Field(..., description="Threat-intelligence provider name.")
    status: ThreatIntelStatus = Field(..., description="Reputation status.")
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Provider confidence in [0, 1]; None if not reported.",
    )
    reason: str | None = Field(
        default=None,
        description="Human-readable reason from the provider.",
    )
    cached: bool = Field(
        default=False,
        description="True if this result was served from the in-memory cache.",
    )
    provider_error: bool = Field(
        default=False,
        description="True if the provider call failed; result should be treated as UNKNOWN.",
    )
    checked_at: datetime = Field(..., description="UTC timestamp when the TI query was made.")


# ---------------------------------------------------------------------------
# Request schema
# ---------------------------------------------------------------------------


class URLScanRequest(BaseModel):
    """Request body for POST /api/v1/analyze/url."""

    url: str = Field(
        ...,
        min_length=1,
        max_length=MAX_URL_LENGTH,
        description=(
            "The URL to analyze.  Must be a valid http:// or https:// URL.  "
            "Maximum length: 2048 characters."
        ),
        examples=["https://example.com/login"],
    )

    @field_validator("url", mode="after")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        """Apply application-level URL validation."""
        try:
            validate_url(v)
        except URLValidationError as exc:
            raise ValueError(exc.detail) from exc
        return v


# ---------------------------------------------------------------------------
# Risk reason schema
# ---------------------------------------------------------------------------


class RiskReason(BaseModel):
    """A single explainable risk indicator."""

    code: ReasonCode = Field(
        ...,
        description="Machine-readable reason code.",
        examples=["IP_HOSTNAME"],
    )
    severity: Severity = Field(
        ...,
        description="Severity level of this indicator.",
        examples=["HIGH"],
    )
    message: str = Field(
        ...,
        description="Human-readable explanation of what was detected and why it matters.",
    )


# ---------------------------------------------------------------------------
# Full scan response
# ---------------------------------------------------------------------------


class URLScanResponse(BaseModel):
    """Full URL analysis result returned by POST /api/v1/analyze/url."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID = Field(..., description="Unique scan identifier.")
    url: str = Field(..., description="The normalized form of the analyzed URL.")
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Risk score in [0, 100].  Higher values indicate greater risk.",
    )
    classification: RiskClassification = Field(
        ...,
        description=(
            "Risk classification tier derived from risk_score.  "
            "Not accepted from the caller — computed server-side."
        ),
    )
    reasons: list[RiskReason] = Field(
        default_factory=list,
        description="Explainable risk indicators.  Empty for low-risk URLs.",
    )
    features: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured feature set extracted from the URL.",
    )
    analyzer_version: str = Field(
        ...,
        description=(
            "Version string identifying the analyzer that produced this result.  "
            "'rule-v1' for M2.  'ml-v1' for M3.  'ml-v1+ti' for M4 with TI enrichment."
        ),
        examples=["ml-v1+ti"],
    )
    # M4 — optional TI enrichment result.  None for historical M0-M3 scans
    # and when threat_intel_enabled=False or TI was skipped.
    threat_intelligence: ThreatIntelSummary | None = Field(
        default=None,
        description=(
            "Threat-intelligence enrichment result (M4). "
            "Null for historical scans and when TI is disabled or unavailable."
        ),
    )
    created_at: datetime = Field(..., description="UTC timestamp of the scan.")


# ---------------------------------------------------------------------------
# History list schemas
# ---------------------------------------------------------------------------


class URLScanSummary(BaseModel):
    """Summary of a single URL scan for display in the history list.

    Returns less detail than ``URLScanResponse`` to avoid exposing full
    feature sets in bulk responses.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID = Field(..., description="Unique scan identifier.")
    url: str = Field(..., description="The normalized form of the analyzed URL.")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score in [0, 100].")
    classification: RiskClassification = Field(..., description="Risk classification tier.")
    analyzer_version: str = Field(..., description="Analyzer version.")
    created_at: datetime = Field(..., description="UTC timestamp of the scan.")


class URLScanHistoryResponse(BaseModel):
    """Paginated scan history response."""

    items: list[URLScanSummary] = Field(
        ..., description="List of URL scan summaries, newest first."
    )
    total: int = Field(..., ge=0, description="Total number of scans for this user.")
    limit: int = Field(..., ge=1, description="Maximum items per page.")
    offset: int = Field(..., ge=0, description="Current page offset.")
