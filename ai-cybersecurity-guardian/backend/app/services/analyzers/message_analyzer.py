"""Message / Phishing Threat Analyzer — M7.

Analyzes text and email messages for social engineering, phishing, and embedded URL threats.
Implements:
- Pure deterministic linguistic & social engineering feature extraction.
- Scikit-learn TF-IDF ML inference with SHA-256 verification and heuristic fallback.
- Reuse of URL analyzer for extracted links (zero duplication of URL threat logic).
- Privacy protection: raw message text is never stored in DB or logged; only SHA-256 is kept.
- Persists to message_scans table isolated by authenticated user_id.
"""

from __future__ import annotations

import hashlib
import uuid

from ml.features.message_features import MessageFeatures, extract_message_features
from ml.inference.message_inference import MessageInferenceEngine
from sqlalchemy.orm import Session

from app.models.message_scan import MessageScan
from app.schemas.unified_analysis import (
    ExplainableReason,
    ExtractedURLAnalysis,
    MessageScanRequest,
    MessageScanResponse,
    ThreatCategory,
)
from app.schemas.url_analysis import RiskClassification, Severity
from app.services.analyzers.base import BaseAnalyzer, NormalizedAnalysisResult
from app.services.analyzers.unified_risk_engine import (
    UnifiedRiskEngine,
    clamp_score,
    score_to_classification,
)
from app.services.analyzers.url_analyzer import URLAnalyzer

# Reusable inference engine singleton
_inference_engine = MessageInferenceEngine()


class MessageAnalyzer(BaseAnalyzer[MessageScanRequest, MessageScanResponse]):
    """Analyzer for phishing messages, email scams, and social engineering."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self._url_analyzer = URLAnalyzer(db)

    @property
    def analyzer_type(self) -> str:
        return "message"

    @property
    def analyzer_version(self) -> str:
        return "message-v1"

    def analyze(self, input_data: MessageScanRequest, user_id: uuid.UUID) -> MessageScanResponse:
        """Analyze message payload and persist result."""
        message_text = input_data.message.strip()
        subject = input_data.subject.strip() if input_data.subject else None
        sender = input_data.sender.strip() if input_data.sender else None

        # Privacy: SHA-256 digest of content
        message_hash = hashlib.sha256(message_text.encode("utf-8")).hexdigest()

        # 1. Feature extraction
        features: MessageFeatures = extract_message_features(
            message=message_text,
            subject=subject,
            sender=sender,
        )

        # 2. Extracted URL analysis (reuse existing URL analyzer)
        extracted_url_results: list[ExtractedURLAnalysis] = []
        max_url_score = 0
        for raw_url in features.extracted_urls[:5]:  # inspect up to 5 URLs safely
            try:
                url_scan = self._url_analyzer.analyze(input_data=raw_url, user_id=user_id)
                extracted_url_results.append(
                    ExtractedURLAnalysis(
                        url=url_scan.url,
                        risk_score=url_scan.risk_score,
                        classification=url_scan.classification,
                    )
                )
                if url_scan.risk_score > max_url_score:
                    max_url_score = url_scan.risk_score
            except Exception:
                # If URL analysis fails (e.g. invalid scheme), treat as suspicious syntax
                extracted_url_results.append(
                    ExtractedURLAnalysis(
                        url=raw_url,
                        risk_score=45,
                        classification=RiskClassification.MEDIUM_RISK,
                    )
                )
                max_url_score = max(max_url_score, 45)

        # 3. ML Inference
        ml_result = _inference_engine.predict(
            message=message_text,
            subject=subject,
            features=features,
        )

        # 4. Rule-based scoring with anti-correlation damping
        reasons: list[ExplainableReason] = []
        rule_score = 0

        # Credential Harvesting
        if features.credential_count > 0:
            contrib = min(30, 20 + (features.credential_count * 5))
            rule_score += contrib
            reasons.append(
                UnifiedRiskEngine.create_reason(
                    category=ThreatCategory.SOCIAL_ENGINEERING,
                    severity=Severity.HIGH if contrib >= 25 else Severity.MEDIUM,
                    title="Credential Harvesting Attempt",
                    explanation=(
                        "Message requests sensitive verification, password changes, "
                        "or account credentials."
                    ),
                    score_contribution=contrib,
                )
            )

        # Urgency & Suspension Threats
        if features.urgency_count > 0 or features.suspension_count > 0:
            contrib = min(25, (features.urgency_count * 10) + (features.suspension_count * 12))
            rule_score += contrib
            reasons.append(
                UnifiedRiskEngine.create_reason(
                    category=ThreatCategory.SOCIAL_ENGINEERING,
                    severity=Severity.HIGH if features.suspension_count > 0 else Severity.MEDIUM,
                    title="Urgency Pressure & Suspension Threats",
                    explanation=(
                        "Message employs psychological urgency or account closure threats "
                        "to provoke immediate action."
                    ),
                    score_contribution=contrib,
                )
            )

        # Financial Pressure & Fraud
        if features.financial_count > 0:
            contrib = min(25, 15 + (features.financial_count * 5))
            rule_score += contrib
            reasons.append(
                UnifiedRiskEngine.create_reason(
                    category=ThreatCategory.SOCIAL_ENGINEERING,
                    severity=Severity.MEDIUM,
                    title="Financial Solicitation or Fraud Indicator",
                    explanation=(
                        "Message references wire transfers, disputed charges, refund claims, "
                        "or crypto transfers."
                    ),
                    score_contribution=contrib,
                )
            )

        # Impersonation
        if features.impersonation_count > 0:
            contrib = 18
            rule_score += contrib
            reasons.append(
                UnifiedRiskEngine.create_reason(
                    category=ThreatCategory.SOCIAL_ENGINEERING,
                    severity=Severity.MEDIUM,
                    title="Corporate or Brand Impersonation",
                    explanation=(
                        "Message claims to originate from security, IT support, "
                        "financial institutions, or known tech providers."
                    ),
                    score_contribution=contrib,
                )
            )

        # Suspicious Metadata / Sender Mismatch
        if features.has_suspicious_sender or features.has_suspicious_subject:
            contrib = 15
            rule_score += contrib
            reasons.append(
                UnifiedRiskEngine.create_reason(
                    category=ThreatCategory.METADATA_MISMATCH,
                    severity=Severity.MEDIUM,
                    title="Sender or Subject Anomaly",
                    explanation=(
                        "Sender address or subject header exhibits mismatch with claimed "
                        "corporate identity or security context."
                    ),
                    score_contribution=contrib,
                )
            )

        # Embedded Malicious / Suspicious URLs
        if max_url_score >= 60:
            contrib = 25
            rule_score += contrib
            reasons.append(
                UnifiedRiskEngine.create_reason(
                    category=ThreatCategory.SUSPICIOUS_URL,
                    severity=Severity.CRITICAL if max_url_score >= 85 else Severity.HIGH,
                    title="High-Risk URL Embedded",
                    explanation=(
                        f"Message contains an embedded link evaluated as high risk "
                        f"(URL Risk Score: {max_url_score})."
                    ),
                    score_contribution=contrib,
                )
            )
        elif len(features.extracted_urls) > 0 and features.call_to_action_count > 0:
            contrib = 10
            rule_score += contrib
            reasons.append(
                UnifiedRiskEngine.create_reason(
                    category=ThreatCategory.LINGUISTIC_PRESSURE,
                    severity=Severity.LOW,
                    title="Call-to-Action Link",
                    explanation="Message prompts recipient to follow external hyperlink.",
                    score_contribution=contrib,
                )
            )

        # Linguistic signals: Excessive uppercase
        if features.uppercase_ratio > 0.25 and features.word_count > 5:
            contrib = 8
            rule_score += contrib
            reasons.append(
                UnifiedRiskEngine.create_reason(
                    category=ThreatCategory.LINGUISTIC_PRESSURE,
                    severity=Severity.LOW,
                    title="Excessive Capitalization",
                    explanation=(
                        "Unusually high proportion of uppercase characters indicating "
                        "high pressure tactics."
                    ),
                    score_contribution=contrib,
                )
            )

        # 5. Unified Signal Fusion
        final_score = UnifiedRiskEngine.fuse_signals(
            base_rule_score=clamp_score(rule_score),
            ml_probability=ml_result.phishing_probability,
            sub_vector_max_score=max_url_score,
        )

        classification = score_to_classification(final_score)

        # 6. Confidence Calibration
        high_sev_count = sum(1 for r in reasons if r.severity in {Severity.HIGH, Severity.CRITICAL})
        calibrated_confidence = UnifiedRiskEngine.calculate_confidence(
            has_ml=not ml_result.used_fallback,
            ml_confidence=ml_result.confidence,
            feature_count=len(reasons),
            high_severity_count=high_sev_count,
        )

        # 7. Persist to DB (User isolated, no raw body stored)
        feature_dict = features.to_dict()
        feature_dict["ml_prediction"] = {
            "phishing_probability": ml_result.phishing_probability,
            "top_contributing_terms": ml_result.top_contributing_terms,
            "used_fallback": ml_result.used_fallback,
        }

        db_reasons = [r.model_dump() for r in reasons]
        db_urls = [u.model_dump() for u in extracted_url_results]

        scan_record = MessageScan(
            user_id=user_id,
            message_hash=message_hash,
            subject=subject[:500] if subject else None,
            sender=sender[:255] if sender else None,
            risk_score=final_score,
            classification=classification.value,
            confidence=calibrated_confidence,
            features=feature_dict,
            reasons=db_reasons,
            extracted_urls=db_urls,
            analyzer_version=self.analyzer_version,
        )

        self.db.add(scan_record)
        self.db.commit()
        self.db.refresh(scan_record)

        # Trigger M8 Incident Correlation (fail-safe)
        try:
            from app.services.intelligence.correlation_engine import CorrelationEngine

            CorrelationEngine(self.db).correlate_message_scan(scan_record)
            self.db.commit()
        except Exception:
            pass

        return MessageScanResponse(
            id=scan_record.id,
            message_hash=message_hash,
            risk_score=final_score,
            classification=classification,
            confidence=calibrated_confidence,
            reasons=reasons,
            features=feature_dict,
            extracted_urls=extracted_url_results,
            analyzer_version=self.analyzer_version,
            created_at=scan_record.created_at,
        )

    def analyze_normalized(
        self, input_data: MessageScanRequest, user_id: uuid.UUID
    ) -> NormalizedAnalysisResult:
        """Execute message analysis returning common normalized result."""
        res = self.analyze(input_data=input_data, user_id=user_id)
        return NormalizedAnalysisResult(
            id=res.id,
            analyzer_type="message",
            risk_score=res.risk_score,
            classification=res.classification,
            confidence=res.confidence,
            reasons=res.reasons,
            extracted_features=res.features,
            analyzer_version=res.analyzer_version,
            created_at=res.created_at,
            processing_metadata={"message_hash": res.message_hash},
        )
