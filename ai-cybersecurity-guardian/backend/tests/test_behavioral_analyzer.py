"""Tests for BehavioralAnalyzer — M8.

Verifies detection of rapid repeated attacks, escalation sequences,
multi-vector progressions, and threat concentrations.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.schemas.url_analysis import RiskClassification
from app.services.intelligence.behavioral_analyzer import (
    BehavioralAnalyzer,
    BehavioralPatternType,
    EventSnapshot,
)


class TestBehavioralAnalyzer:
    """Test suite for behavioral pattern detection."""

    def test_rapid_repeat_attacks_detected(self) -> None:
        now = datetime.now(UTC)
        events = [
            EventSnapshot(
                event_id="e1",
                event_type="url_scan",
                risk_score=90,
                classification=RiskClassification.CRITICAL.value,
                created_at=now - timedelta(minutes=10),
                indicator_values={"evil.com"},
            ),
            EventSnapshot(
                event_id="e2",
                event_type="url_scan",
                risk_score=85,
                classification=RiskClassification.HIGH_RISK.value,
                created_at=now - timedelta(minutes=5),
                indicator_values={"evil.com"},
            ),
            EventSnapshot(
                event_id="e3",
                event_type="url_scan",
                risk_score=95,
                classification=RiskClassification.CRITICAL.value,
                created_at=now - timedelta(minutes=1),
                indicator_values={"evil.com"},
            ),
        ]

        findings = BehavioralAnalyzer.analyze_events(events)
        patterns = {f.pattern for f in findings}
        assert BehavioralPatternType.RAPID_REPEAT_ATTACKS in patterns

    def test_severity_escalation_detected(self) -> None:
        now = datetime.now(UTC)
        events = [
            EventSnapshot(
                event_id="e1",
                event_type="url_scan",
                risk_score=40,
                classification=RiskClassification.MEDIUM_RISK.value,
                created_at=now - timedelta(minutes=20),
                indicator_values={"target.com"},
            ),
            EventSnapshot(
                event_id="e2",
                event_type="url_scan",
                risk_score=65,
                classification=RiskClassification.HIGH_RISK.value,
                created_at=now - timedelta(minutes=12),
                indicator_values={"target.com"},
            ),
            EventSnapshot(
                event_id="e3",
                event_type="url_scan",
                risk_score=88,
                classification=RiskClassification.CRITICAL.value,
                created_at=now - timedelta(minutes=2),
                indicator_values={"target.com"},
            ),
        ]

        findings = BehavioralAnalyzer.analyze_events(events)
        patterns = {f.pattern for f in findings}
        assert BehavioralPatternType.SEVERITY_ESCALATION in patterns

    def test_multi_vector_progression_detected(self) -> None:
        now = datetime.now(UTC)
        events = [
            EventSnapshot(
                event_id="e1",
                event_type="message_scan",
                risk_score=70,
                classification=RiskClassification.HIGH_RISK.value,
                created_at=now - timedelta(minutes=40),
                indicator_values={"phish-update.xyz"},
            ),
            EventSnapshot(
                event_id="e2",
                event_type="url_scan",
                risk_score=85,
                classification=RiskClassification.HIGH_RISK.value,
                created_at=now - timedelta(minutes=20),
                indicator_values={"phish-update.xyz"},
            ),
        ]

        findings = BehavioralAnalyzer.analyze_events(events)
        patterns = {f.pattern for f in findings}
        assert BehavioralPatternType.MULTI_VECTOR_PROGRESSION in patterns

    def test_threat_concentration_detected(self) -> None:
        now = datetime.now(UTC)
        events = [
            EventSnapshot(
                event_id=f"e{i}",
                event_type="url_scan",
                risk_score=75,
                classification=RiskClassification.HIGH_RISK.value,
                created_at=now - timedelta(hours=i),
                indicator_values={"malicious-campaign.ru"},
            )
            for i in range(5)
        ]

        findings = BehavioralAnalyzer.analyze_events(events)
        patterns = {f.pattern for f in findings}
        assert BehavioralPatternType.THREAT_CONCENTRATION in patterns

    def test_clean_or_sparse_events_yield_no_findings(self) -> None:
        now = datetime.now(UTC)
        events = [
            EventSnapshot(
                event_id="e1",
                event_type="url_scan",
                risk_score=10,
                classification=RiskClassification.LOW_RISK.value,
                created_at=now - timedelta(days=2),
                indicator_values={"google.com"},
            ),
            EventSnapshot(
                event_id="e2",
                event_type="url_scan",
                risk_score=15,
                classification=RiskClassification.LOW_RISK.value,
                created_at=now,
                indicator_values={"github.com"},
            ),
        ]

        findings = BehavioralAnalyzer.analyze_events(events)
        assert findings == []
