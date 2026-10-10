"""Unit tests for Unified Threat Risk Scoring Engine — M7."""

from __future__ import annotations

from app.schemas.unified_analysis import ThreatCategory
from app.schemas.url_analysis import RiskClassification, Severity
from app.services.analyzers.unified_risk_engine import (
    UnifiedRiskEngine,
    clamp_confidence,
    clamp_score,
    score_to_classification,
)


class TestUnifiedRiskEngine:
    def test_score_clamping(self) -> None:
        assert clamp_score(-10) == 0
        assert clamp_score(0) == 0
        assert clamp_score(55) == 55
        assert clamp_score(100) == 100
        assert clamp_score(150) == 100

    def test_confidence_clamping(self) -> None:
        assert clamp_confidence(-0.5) == 0.0
        assert clamp_confidence(0.8546) == 0.855
        assert clamp_confidence(1.5) == 1.0

    def test_classification_thresholds(self) -> None:
        assert score_to_classification(0) == RiskClassification.LOW_RISK
        assert score_to_classification(29) == RiskClassification.LOW_RISK
        assert score_to_classification(30) == RiskClassification.MEDIUM_RISK
        assert score_to_classification(59) == RiskClassification.MEDIUM_RISK
        assert score_to_classification(60) == RiskClassification.HIGH_RISK
        assert score_to_classification(84) == RiskClassification.HIGH_RISK
        assert score_to_classification(85) == RiskClassification.CRITICAL
        assert score_to_classification(100) == RiskClassification.CRITICAL

    def test_signal_fusion_without_double_counting(self) -> None:
        # Rule score 40, ML proba 0.80 (80 points) -> blended (0.55*40 + 0.45*80) = 22 + 36 = 58
        fused = UnifiedRiskEngine.fuse_signals(base_rule_score=40, ml_probability=0.80)
        assert fused == 58

        # When sub-vector score is high (e.g. 90), result reflects the high-risk link
        fused_with_sub = UnifiedRiskEngine.fuse_signals(
            base_rule_score=40,
            ml_probability=0.80,
            sub_vector_max_score=90,
        )
        assert fused_with_sub >= 81

    def test_anti_correlation_damping(self) -> None:
        contributions = [
            ("urgency", 20, 0.5),
            ("urgency", 20, 0.5),  # 2nd urgency indicator should be damped (20 * 0.5 = 10)
            ("urgency", 20, 0.5),  # 3rd urgency indicator should be damped (20 * 0.25 = 5)
            ("credential", 30, 0.5),  # separate group is not damped
        ]
        damped = UnifiedRiskEngine.damp_correlated_contributions(contributions)
        assert damped == [20, 10, 5, 30]

    def test_create_reason_validation(self) -> None:
        reason = UnifiedRiskEngine.create_reason(
            category=ThreatCategory.SOCIAL_ENGINEERING,
            severity=Severity.HIGH,
            title="Credential Harvest",
            explanation="Test explanation",
            score_contribution=25,
        )
        assert reason.category == ThreatCategory.SOCIAL_ENGINEERING
        assert reason.severity == Severity.HIGH
        assert reason.score_contribution == 25
