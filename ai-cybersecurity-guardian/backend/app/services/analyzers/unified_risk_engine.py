"""Unified Threat Risk Scoring Engine — M7.

Provides centralized risk fusion, anti-correlation signal damping, confidence
calibration, server-side classification, and structured explainability.
"""

from __future__ import annotations

import math
from collections.abc import Sequence

from app.schemas.unified_analysis import ExplainableReason, ThreatCategory
from app.schemas.url_analysis import RiskClassification, Severity

# ---------------------------------------------------------------------------
# Classification thresholds
# ---------------------------------------------------------------------------

LOW_THRESHOLD = 30
MEDIUM_THRESHOLD = 60
HIGH_THRESHOLD = 85


def score_to_classification(score: int) -> RiskClassification:
    """Map numeric score in [0, 100] to risk tier."""
    if score < LOW_THRESHOLD:
        return RiskClassification.LOW_RISK
    if score < MEDIUM_THRESHOLD:
        return RiskClassification.MEDIUM_RISK
    if score < HIGH_THRESHOLD:
        return RiskClassification.HIGH_RISK
    return RiskClassification.CRITICAL


def clamp_score(score: float | int) -> int:
    """Strictly clamp any numeric score to integer in [0, 100]."""
    return max(0, min(100, int(round(score))))


def clamp_confidence(confidence: float) -> float:
    """Strictly clamp confidence value to float in [0.0, 1.0]."""
    return max(0.0, min(1.0, round(confidence, 3)))


class UnifiedRiskEngine:
    """Centralized multi-signal threat scoring engine."""

    @staticmethod
    def fuse_signals(
        base_rule_score: int,
        ml_probability: float | None = None,
        ti_boost: int = 0,
        sub_vector_max_score: int = 0,
    ) -> int:
        """Fuse multiple detection signals without double counting.

        Parameters
        ----------
        base_rule_score:
            Deterministic rule-based risk score [0, 100].
        ml_probability:
            Optional ML probability [0.0, 1.0]. None if ML is skipped/unavailable.
        ti_boost:
            Threat intelligence boost points [0, 30].
        sub_vector_max_score:
            Maximum risk score from any nested sub-vectors (e.g. extracted URL in a message).

        Returns
        -------
        final_score:
            Fused and clamped score in [0, 100].
        """
        # If ML probability is available, combine rule baseline and ML probability
        if ml_probability is not None:
            ml_points = ml_probability * 100.0
            # Weighted blend: 55% rules + 45% ML to balance deterministic explainability
            blended = (0.55 * float(base_rule_score)) + (0.45 * ml_points)
        else:
            blended = float(base_rule_score)

        # Non-linear damping for sub-vectors (e.g., malicious URL in message)
        # If message contains a high-risk URL, ensure message score reflects this danger
        if sub_vector_max_score > 0:
            if sub_vector_max_score >= 60:
                # Strong pull towards the nested risk
                blended = max(blended, sub_vector_max_score * 0.9)
            else:
                # Modest boost if nested URL is suspicious
                blended += sub_vector_max_score * 0.25

        # Threat intelligence corroboration
        blended += float(ti_boost)

        return clamp_score(blended)

    @staticmethod
    def damp_correlated_contributions(
        contributions: Sequence[tuple[str, int, float]],
    ) -> list[int]:
        """Apply diminishing returns to correlated threat indicators.

        Parameters
        ----------
        contributions:
            List of (group_key, raw_score, damping_factor).
            When multiple indicators in the same group_key fire, subsequent ones
            are scaled down by damping_factor^(occurrence_index).

        Returns
        -------
        damped_scores:
            List of integer damped score contributions.
        """
        seen_counts: dict[str, int] = {}
        damped_scores: list[int] = []

        for group_key, raw_score, factor in contributions:
            count = seen_counts.get(group_key, 0)
            multiplier = math.pow(factor, count)
            damped = int(round(raw_score * multiplier))
            damped_scores.append(max(0, damped))
            seen_counts[group_key] = count + 1

        return damped_scores

    @staticmethod
    def calculate_confidence(
        has_ml: bool,
        ml_confidence: float | None,
        feature_count: int,
        high_severity_count: int,
    ) -> float:
        """Calibrate detection confidence in [0.0, 1.0].

        Separates confidence (how sure we are in the verdict) from risk score (how dangerous).
        """
        base_confidence = 0.70

        if has_ml and ml_confidence is not None:
            # Anchor to ML confidence
            base_confidence = 0.50 + (0.50 * ml_confidence)

        # Boost confidence when multiple strong indicators corroborate
        if high_severity_count >= 2:
            base_confidence += 0.15
        elif high_severity_count == 1:
            base_confidence += 0.08

        # Minor boost for comprehensive feature coverage
        if feature_count >= 5:
            base_confidence += 0.05

        return clamp_confidence(base_confidence)

    @staticmethod
    def create_reason(
        category: ThreatCategory,
        severity: Severity,
        title: str,
        explanation: str,
        score_contribution: int,
    ) -> ExplainableReason:
        """Create a validated explainable reason model."""
        return ExplainableReason(
            category=category,
            severity=severity,
            title=title,
            explanation=explanation,
            score_contribution=clamp_score(score_contribution),
        )
