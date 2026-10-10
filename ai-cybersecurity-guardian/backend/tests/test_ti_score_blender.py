"""Tests for score_blender module — M4.

Verifies:
- MALICIOUS → score increase bounded by max_boost
- SUSPICIOUS → score increase bounded by max_boost // 2
- CLEAN → no score change
- UNKNOWN → no score change
- provider_error → no score change
- Final score always in [0, 100]
- Correct RiskReason codes generated
- Confidence scaling
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

os.environ.setdefault("JWT_SECRET", "test-jwt-secret-at-least-32-chars-long-here")
os.environ.setdefault("ENVIRONMENT", "test")

import pytest
from app.services import score_blender
from app.services.ti_types import ThreatIntelResult, ThreatIntelStatus


def _make_result(
    status: ThreatIntelStatus,
    confidence: float | None = 1.0,
    provider_error: bool = False,
    reason: str | None = None,
    cached: bool = False,
) -> ThreatIntelResult:
    return ThreatIntelResult(
        provider="mock",
        status=status,
        confidence=confidence,
        reason=reason,
        checked_at=datetime.now(UTC),
        provider_error=provider_error,
        cached=cached,
    )


class TestScoreBlendMalicious:
    def test_malicious_full_confidence_boosts_by_max(self) -> None:
        score, _ = score_blender.blend(50, _make_result(ThreatIntelStatus.MALICIOUS, 1.0),
            max_boost=30)
        assert score == 80

    def test_malicious_half_confidence_boosts_by_half(self) -> None:
        score, _ = score_blender.blend(50, _make_result(ThreatIntelStatus.MALICIOUS, 0.5),
            max_boost=30)
        assert score == 65  # 50 + round(30 * 0.5) = 50 + 15 = 65

    def test_malicious_zero_confidence_no_boost(self) -> None:
        score, _ = score_blender.blend(50, _make_result(ThreatIntelStatus.MALICIOUS, 0.0),
            max_boost=30)
        assert score == 50

    def test_malicious_clamped_at_100(self) -> None:
        score, _ = score_blender.blend(90, _make_result(ThreatIntelStatus.MALICIOUS, 1.0),
            max_boost=30)
        assert score == 100

    def test_malicious_generates_reason(self) -> None:
        _, reasons = score_blender.blend(50, _make_result(ThreatIntelStatus.MALICIOUS, 1.0))
        assert len(reasons) == 1
        assert reasons[0]["code"] == "TI_REPUTATION"
        assert reasons[0]["severity"] == "CRITICAL"

    def test_malicious_reason_contains_provider_name(self) -> None:
        _, reasons = score_blender.blend(50, _make_result(ThreatIntelStatus.MALICIOUS, 1.0))
        assert "mock" in reasons[0]["message"]

    def test_malicious_reason_contains_boost_amount(self) -> None:
        _, reasons = score_blender.blend(50, _make_result(ThreatIntelStatus.MALICIOUS, 1.0),
            max_boost=30)
        assert "30" in reasons[0]["message"]


class TestScoreBlendSuspicious:
    def test_suspicious_full_confidence_boosts_by_half_max(self) -> None:
        score, _ = score_blender.blend(50, _make_result(ThreatIntelStatus.SUSPICIOUS, 1.0),
            max_boost=30)
        assert score == 65  # 50 + 15

    def test_suspicious_half_confidence(self) -> None:
        score, _ = score_blender.blend(50, _make_result(ThreatIntelStatus.SUSPICIOUS, 0.5),
            max_boost=30)
        assert score == 58  # 50 + round(15 * 0.5) = 50 + 8 = 58

    def test_suspicious_generates_high_severity_reason(self) -> None:
        _, reasons = score_blender.blend(50, _make_result(ThreatIntelStatus.SUSPICIOUS, 1.0))
        assert len(reasons) == 1
        assert reasons[0]["severity"] == "HIGH"

    def test_suspicious_reason_code_is_ti_reputation(self) -> None:
        _, reasons = score_blender.blend(50, _make_result(ThreatIntelStatus.SUSPICIOUS, 1.0))
        assert reasons[0]["code"] == "TI_REPUTATION"


class TestScoreBlendClean:
    def test_clean_does_not_increase_score(self) -> None:
        score, _ = score_blender.blend(80, _make_result(ThreatIntelStatus.CLEAN, 0.9))
        assert score == 80

    def test_clean_does_not_decrease_score(self) -> None:
        score, _ = score_blender.blend(5, _make_result(ThreatIntelStatus.CLEAN, 1.0))
        assert score == 5

    def test_clean_generates_informational_reason(self) -> None:
        _, reasons = score_blender.blend(50, _make_result(ThreatIntelStatus.CLEAN, 0.9))
        assert len(reasons) == 1
        assert reasons[0]["code"] == "TI_REPUTATION"
        assert reasons[0]["severity"] == "LOW"


class TestScoreBlendUnknownAndError:
    def test_unknown_no_change(self) -> None:
        score, reasons = score_blender.blend(60, _make_result(ThreatIntelStatus.UNKNOWN))
        assert score == 60
        assert reasons == []

    def test_provider_error_no_change(self) -> None:
        score, reasons = score_blender.blend(
            75,
            _make_result(ThreatIntelStatus.MALICIOUS, provider_error=True),
        )
        assert score == 75
        assert reasons == []

    def test_unknown_no_confidence_no_change(self) -> None:
        score, reasons = score_blender.blend(
            60,
            _make_result(ThreatIntelStatus.UNKNOWN, confidence=None),
        )
        assert score == 60


class TestScoreBlendBoundaries:
    @pytest.mark.parametrize("baseline", [0, 1, 50, 99, 100])
    def test_score_always_0_to_100(self, baseline: int) -> None:
        score, _ = score_blender.blend(
            baseline,
            _make_result(ThreatIntelStatus.MALICIOUS, 1.0),
            max_boost=30,
        )
        assert 0 <= score <= 100

    def test_baseline_0_malicious_boosts_correctly(self) -> None:
        score, _ = score_blender.blend(0, _make_result(ThreatIntelStatus.MALICIOUS, 1.0),
            max_boost=30)
        assert score == 30

    def test_custom_max_boost_respected(self) -> None:
        score, _ = score_blender.blend(50, _make_result(ThreatIntelStatus.MALICIOUS, 1.0),
            max_boost=10)
        assert score == 60

    def test_zero_max_boost_no_change(self) -> None:
        score, _ = score_blender.blend(50, _make_result(ThreatIntelStatus.MALICIOUS, 1.0),
            max_boost=0)
        assert score == 50


class TestScoreBlendReasonDetails:
    def test_reason_includes_provider_reason_when_present(self) -> None:
        _, reasons = score_blender.blend(
            50,
            _make_result(ThreatIntelStatus.MALICIOUS, 1.0, reason="Flagged by 10/70 engines"),
        )
        assert "Flagged by 10/70 engines" in reasons[0]["message"]

    def test_cached_result_noted_in_reason(self) -> None:
        _, reasons = score_blender.blend(
            50,
            _make_result(ThreatIntelStatus.MALICIOUS, 1.0, cached=True),
        )
        assert "cached" in reasons[0]["message"].lower()

    def test_non_cached_no_cache_note(self) -> None:
        _, reasons = score_blender.blend(
            50,
            _make_result(ThreatIntelStatus.MALICIOUS, 1.0, cached=False),
        )
        assert "cached" not in reasons[0]["message"].lower()
