"""URL Analyzer Adapter — M7 Multi-Vector Architecture.

Adapts the existing M2–M4 ``URLAnalyzerService`` to the ``BaseAnalyzer`` interface
while preserving 100% of existing behavior, schemas, and endpoints.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.schemas.unified_analysis import ExplainableReason, ThreatCategory
from app.schemas.url_analysis import ReasonCode, Severity, URLScanResponse
from app.services.analyzers.base import BaseAnalyzer, NormalizedAnalysisResult
from app.services.url_analyzer import URLAnalyzerService

# Reason code to ThreatCategory mapping for unified explainability
_REASON_CATEGORY_MAP: dict[ReasonCode, ThreatCategory] = {
    ReasonCode.HTTP_NOT_HTTPS: ThreatCategory.METADATA_MISMATCH,
    ReasonCode.IP_HOSTNAME: ThreatCategory.SUSPICIOUS_URL,
    ReasonCode.PUNYCODE_DOMAIN: ThreatCategory.SUSPICIOUS_URL,
    ReasonCode.EXCESSIVE_SUBDOMAINS: ThreatCategory.SUSPICIOUS_URL,
    ReasonCode.SUSPICIOUS_TLD: ThreatCategory.SUSPICIOUS_URL,
    ReasonCode.SUSPICIOUS_KEYWORD: ThreatCategory.SOCIAL_ENGINEERING,
    ReasonCode.CREDENTIAL_PATH: ThreatCategory.SOCIAL_ENGINEERING,
    ReasonCode.USERINFO_PRESENT: ThreatCategory.SUSPICIOUS_URL,
    ReasonCode.NON_STANDARD_PORT: ThreatCategory.SUSPICIOUS_URL,
    ReasonCode.EXCESSIVE_URL_LENGTH: ThreatCategory.SUSPICIOUS_URL,
    ReasonCode.HIGH_ENCODING_RATIO: ThreatCategory.SUSPICIOUS_URL,
    ReasonCode.SUSPICIOUS_COMBINATION: ThreatCategory.SUSPICIOUS_URL,
    ReasonCode.TI_REPUTATION: ThreatCategory.THREAT_INTEL,
}


class URLAnalyzer(BaseAnalyzer[str, URLScanResponse]):
    """Multi-vector adapter for URL threat analysis."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self._service = URLAnalyzerService(db)

    @property
    def analyzer_type(self) -> str:
        return "url"

    @property
    def analyzer_version(self) -> str:
        return "url-ml-v1"

    def analyze(self, input_data: str, user_id: uuid.UUID) -> URLScanResponse:
        """Execute URL analysis via URLAnalyzerService."""
        return self._service.analyze(url=input_data, user_id=user_id)

    def analyze_normalized(self, input_data: str, user_id: uuid.UUID) -> NormalizedAnalysisResult:
        """Execute URL analysis and return standardized multi-vector result."""
        res = self.analyze(input_data=input_data, user_id=user_id)

        # Convert RiskReason list to ExplainableReason list
        explainable_reasons: list[ExplainableReason] = []
        for r in res.reasons:
            cat = _REASON_CATEGORY_MAP.get(r.code, ThreatCategory.SUSPICIOUS_URL)
            if r.severity == Severity.HIGH:
                contrib = 15
            elif r.severity == Severity.MEDIUM:
                contrib = 10
            else:
                contrib = 5
            explainable_reasons.append(
                ExplainableReason(
                    category=cat,
                    severity=r.severity,
                    title=r.code.replace("_", " ").title(),
                    explanation=r.message,
                    score_contribution=contrib,
                )
            )

        # Calibrate confidence based on TI presence and risk score
        has_ti = (
            res.threat_intelligence is not None
            and res.threat_intelligence.status.value != "UNKNOWN"
        )
        confidence = 0.90 if has_ti else 0.80

        return NormalizedAnalysisResult(
            id=res.id,
            analyzer_type="url",
            risk_score=res.risk_score,
            classification=res.classification,
            confidence=confidence,
            reasons=explainable_reasons,
            extracted_features=res.features,
            analyzer_version=res.analyzer_version,
            created_at=res.created_at,
            processing_metadata={"normalized_url": res.url},
        )
