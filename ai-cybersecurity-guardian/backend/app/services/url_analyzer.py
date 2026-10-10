"""URL analyzer service — M2/M3/M4.

This service orchestrates the URL analysis pipeline:

    1. Validate + normalize the raw URL
    2. Compute SHA-256 hash of the normalized URL
    3. Extract URL features (pure / stateless)
    4. Run inference (ML engine in M3; rule engine fallback)
    5. Threat Intelligence enrichment (M4 — optional, never crashes analysis)
    6. Blend ML score with TI signal
    7. Persist the URLScan row + ThreatIntelligenceResult row (if TI performed)
    8. Return the structured response

Authorization enforcement
-------------------------
``analyze()`` and ``get_history()`` both require the caller to supply the
authenticated ``user_id``.  The service NEVER trusts a ``user_id`` from the
request body — it always reads from the authenticated session via
``get_current_user`` in the API layer.

``get_history()`` enforces ``WHERE user_id = current_user.id`` at the query
level so users can never read each other's scans.

SSRF safety
-----------
This service performs NO network requests to the submitted URL.  The analyzer
pipeline is a pure string-processing pipeline.  The ``URLInferenceEngine``
and all upstream code are statically verified to contain no HTTP client calls.

The threat-intelligence provider makes HTTP calls to a fixed, hard-coded
provider endpoint (VirusTotal API or mock).  The submitted URL is sent to
the provider only in sanitized form (userinfo stripped).  Provider calls
are wrapped in a ``ThreatIntelligenceService`` that isolates all failures.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import sys
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.url_utils import hash_url, normalize_url, validate_url
from app.models.threat_intel import ThreatIntelligenceResult
from app.models.url_scan import URLScan
from app.schemas.url_analysis import (
    ReasonCode,
    RiskClassification,
    RiskReason,
    Severity,
    ThreatIntelStatus,
    ThreatIntelSummary,
    URLScanHistoryResponse,
    URLScanResponse,
    URLScanSummary,
)
from app.services import score_blender
from app.services.threat_intelligence import ThreatIntelligenceService
from app.services.ti_cache import ThreatIntelCache
from app.services.ti_providers.mock_provider import MockProvider
from app.services.ti_providers.virustotal_provider import VirusTotalProvider
from app.services.ti_types import ThreatIntelResult

# Add the project root to sys.path so the `ml` package is importable.
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from ml.features import url_features  # noqa: E402
from ml.inference.url_inference import URLInferenceEngine  # noqa: E402

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HISTORY_MAX_LIMIT = 100
HISTORY_DEFAULT_LIMIT = 20

# Module-level inference engine singleton (stateless, thread-safe)
_inference_engine = URLInferenceEngine()

# ---------------------------------------------------------------------------
# Module-level TI singletons (built once; settings drive provider selection)
# ---------------------------------------------------------------------------


def _build_ti_service() -> ThreatIntelligenceService | None:
    """Build the ThreatIntelligenceService from current settings.

    Returns None if TI is disabled (kill-switch off).
    """
    settings = get_settings()
    if not settings.threat_intel_enabled:
        logger.info("Threat intelligence is disabled (THREAT_INTEL_ENABLED=false).")
        return None

    api_key = settings.virustotal_api_key
    if api_key:
        logger.info("Threat intelligence: using VirusTotal provider.")
        provider: Any = VirusTotalProvider(api_key=api_key)
    else:
        logger.info("Threat intelligence: VIRUSTOTAL_API_KEY not set, using mock provider.")
        provider = MockProvider()

    cache = ThreatIntelCache(
        ttl_seconds=settings.threat_intel_cache_ttl_seconds,
        max_size=10_000,
    )
    return ThreatIntelligenceService(
        provider=provider,
        cache=cache,
        timeout_seconds=settings.threat_intel_timeout_seconds,
    )


# Singleton — built once at module load time.
# Tests can replace this to inject a mock.
_ti_service: ThreatIntelligenceService | None = _build_ti_service()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _features_to_dict(features: url_features.URLFeatures) -> dict[str, Any]:
    """Convert URLFeatures dataclass to a JSON-serializable dict."""
    d = dataclasses.asdict(features)
    # Convert tuple fields to lists for JSON compatibility
    d["suspicious_keywords_found"] = list(features.suspicious_keywords_found)
    d["credential_keywords_in_path"] = list(features.credential_keywords_in_path)
    return d


def _risk_reasons_to_schema(
    engine_reasons: list[Any],
) -> list[RiskReason]:
    """Convert engine RiskReason objects to API schema RiskReason objects."""
    result: list[RiskReason] = [
        RiskReason(
            code=ReasonCode(r.code.value),
            severity=Severity(r.severity.value),
            message=r.message,
        )
        for r in engine_reasons
    ]
    return result


def _ti_reasons_to_schema(ti_reasons: list[dict[str, str]]) -> list[RiskReason]:
    """Convert score_blender reason dicts to RiskReason schema objects."""
    return [
        RiskReason(
            code=ReasonCode(r["code"]),
            severity=Severity(r["severity"]),
            message=r["message"],
        )
        for r in ti_reasons
    ]


def _classification_from_score(score: int) -> RiskClassification:
    """Derive classification from a blended score (M4 thresholds unchanged)."""
    if score >= 75:
        return RiskClassification.CRITICAL
    if score >= 50:
        return RiskClassification.HIGH_RISK
    if score >= 25:
        return RiskClassification.MEDIUM_RISK
    return RiskClassification.LOW_RISK


def _classification_to_schema(cls_str: str) -> RiskClassification:
    return RiskClassification(cls_str)


def _ti_result_to_summary(ti_result: ThreatIntelResult) -> ThreatIntelSummary:
    """Convert a ThreatIntelResult to the API ThreatIntelSummary schema."""
    return ThreatIntelSummary(
        provider=ti_result.provider,
        status=ThreatIntelStatus(ti_result.status.value),
        confidence=ti_result.confidence,
        reason=ti_result.reason,
        cached=ti_result.cached,
        provider_error=ti_result.provider_error,
        checked_at=ti_result.checked_at,
    )


def _analyzer_version_with_ti(base_version: str, ti_result: ThreatIntelResult | None) -> str:
    """Return the analyzer version string reflecting TI enrichment.

    Historical rules:
    - rule-v1  → M2 (no TI)
    - ml-v1    → M3 (no TI)
    - ml-v1+ti → M4 with successful TI enrichment
    - rule-v1+ti → M4 with rule fallback + TI enrichment

    TI errors or disabled TI → base_version unchanged.
    """
    if ti_result is None or ti_result.provider_error:
        return base_version
    return f"{base_version}+ti"


# ---------------------------------------------------------------------------
# URLAnalyzerService
# ---------------------------------------------------------------------------


class URLAnalyzerService:
    """Orchestrates URL analysis, persistence, and history retrieval.

    Instantiate with the current database session::

        svc = URLAnalyzerService(db)
        result = svc.analyze(url="https://example.com", user_id=user.id)
    """

    def __init__(
        self,
        db: Session,
        ti_service: ThreatIntelligenceService | None = None,
    ) -> None:
        self._db = db
        # Allow injection in tests; fall back to module-level singleton.
        self._ti_service = ti_service if ti_service is not None else _ti_service

    def analyze(self, url: str, user_id: uuid.UUID) -> URLScanResponse:
        """Analyze a URL and persist the result.

        Parameters
        ----------
        url:
            Raw URL string from the request body.
        user_id:
            Authenticated user's ID.  MUST be read from the session — never
            from the request body.

        Returns
        -------
        URLScanResponse:
            Full analysis result including score, classification, reasons,
            features, analyzer version, and optional TI summary.

        Raises
        ------
        URLValidationError:
            If the URL is invalid.  The caller should translate this to a
            422 Unprocessable Entity response.
        """
        settings = get_settings()

        # Step 1 — validate (raises URLValidationError on failure)
        validate_url(url)

        # Step 2 — normalize
        normalized = normalize_url(url)

        # Step 3 — hash
        url_hash = hash_url(normalized)

        # Step 4 — extract features (pure / stateless)
        features = url_features.extract(normalized)

        # Step 5 — run inference (pure / stateless)
        inference_result = _inference_engine.run(features)
        baseline_score = inference_result.score
        base_version = inference_result.analyzer_version

        # Step 6 — Threat Intelligence enrichment (M4)
        ti_result: ThreatIntelResult | None = None
        ti_reasons: list[RiskReason] = []
        final_score = baseline_score

        if self._ti_service is not None:
            try:
                ti_result = self._ti_service.enrich(
                    url_hash=url_hash,
                    normalized_url=normalized,
                )
                final_score, raw_ti_reasons = score_blender.blend(
                    baseline_score,
                    ti_result,
                    max_boost=settings.threat_intel_max_boost,
                )
                ti_reasons = _ti_reasons_to_schema(raw_ti_reasons)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "TI enrichment failed unexpectedly (url_hash=%.16s...): %s",
                    url_hash,
                    type(exc).__name__,
                )
                ti_result = None

        # Step 7 — Derive final classification from blended score
        final_classification = _classification_from_score(final_score)
        analyzer_version = _analyzer_version_with_ti(base_version, ti_result)

        # Step 8 — Convert to serializable form
        features_dict = _features_to_dict(features)
        engine_reasons = _risk_reasons_to_schema(inference_result.reasons)
        all_reasons = engine_reasons + ti_reasons
        reasons_dict = [
            {
                "code": r.code.value,
                "severity": r.severity.value,
                "message": r.message,
            }
            for r in all_reasons
        ]

        # Step 9 — Persist URLScan
        scan = URLScan(
            id=uuid.uuid4(),
            user_id=user_id,
            url_hash=url_hash,
            normalized_url=normalized,
            risk_score=final_score,
            classification=final_classification.value,
            features=features_dict,
            reasons=reasons_dict,
            analyzer_version=analyzer_version,
        )
        self._db.add(scan)
        self._db.flush()  # flush to get scan.id before creating TI row

        # Step 10 — Persist TI result (separate table, never modifies scan row)
        if ti_result is not None:
            ti_row = ThreatIntelligenceResult(
                id=uuid.uuid4(),
                scan_id=scan.id,
                provider=ti_result.provider,
                status=ti_result.status.value,
                confidence=ti_result.confidence,
                reason=ti_result.reason,
                cached=ti_result.cached,
                provider_error=ti_result.provider_error,
                checked_at=ti_result.checked_at,
            )
            self._db.add(ti_row)

        self._db.commit()
        self._db.refresh(scan)

        # Step 10.5 — Trigger M8 Incident Correlation (fail-safe)
        try:
            from app.services.intelligence.correlation_engine import CorrelationEngine

            CorrelationEngine(self._db).correlate_url_scan(scan)
            self._db.commit()
        except Exception:
            pass

        # Step 11 — Build response
        ti_summary: ThreatIntelSummary | None = (
            _ti_result_to_summary(ti_result) if ti_result is not None else None
        )

        return URLScanResponse(
            id=scan.id,
            url=normalized,
            risk_score=final_score,
            classification=final_classification,
            reasons=all_reasons,
            features=features_dict,
            analyzer_version=analyzer_version,
            threat_intelligence=ti_summary,
            created_at=scan.created_at if scan.created_at else datetime.now(UTC),
        )

    def get_history(
        self,
        user_id: uuid.UUID,
        limit: int = HISTORY_DEFAULT_LIMIT,
        offset: int = 0,
    ) -> URLScanHistoryResponse:
        """Return paginated scan history for the authenticated user.

        Authorization: enforces ``WHERE user_id = :user_id`` at query level.
        Users can NEVER read another user's scans.

        Parameters
        ----------
        user_id:
            Authenticated user's ID.  Read from the session — never from
            the request.
        limit:
            Maximum items to return.  Clamped to ``HISTORY_MAX_LIMIT``.
        offset:
            Pagination offset.

        Returns
        -------
        URLScanHistoryResponse:
            Paginated list of scan summaries, newest first.
        """
        # Clamp limit to prevent abuse
        safe_limit = max(1, min(limit, HISTORY_MAX_LIMIT))
        safe_offset = max(0, offset)

        # Count total (for pagination metadata)
        total_stmt = select(func.count()).select_from(URLScan).where(URLScan.user_id == user_id)
        total: int = self._db.execute(total_stmt).scalar_one()

        # Fetch page — newest first
        stmt = (
            select(URLScan)
            .where(URLScan.user_id == user_id)
            .order_by(URLScan.created_at.desc())
            .limit(safe_limit)
            .offset(safe_offset)
        )
        scans = self._db.execute(stmt).scalars().all()

        items = [
            URLScanSummary(
                id=scan.id,
                url=scan.normalized_url,
                risk_score=scan.risk_score,
                classification=_classification_to_schema(scan.classification),
                analyzer_version=scan.analyzer_version,
                created_at=scan.created_at,
            )
            for scan in scans
        ]

        return URLScanHistoryResponse(
            items=items,
            total=total,
            limit=safe_limit,
            offset=safe_offset,
        )
