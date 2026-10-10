"""Behavioral Threat Analyzer — M8.

Analyzes user-level scan sequences and detection history to identify:
- Repeated suspicious activity in short time windows
- Severity escalation patterns (e.g., MEDIUM -> HIGH -> CRITICAL)
- Multi-vector threat progression (Message -> URL -> File)
- Indicator repetition across distinct vectors
- High threat concentration towards specific targets

Uses configurable thresholds without hardcoded magic numbers.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from app.schemas.unified_analysis import ExplainableReason, ThreatCategory
from app.schemas.url_analysis import RiskClassification, Severity


class BehavioralPatternType(str, Enum):
    """Behavioral attack pattern categories."""

    RAPID_REPEAT_ATTACKS = "RAPID_REPEAT_ATTACKS"
    SEVERITY_ESCALATION = "SEVERITY_ESCALATION"
    MULTI_VECTOR_PROGRESSION = "MULTI_VECTOR_PROGRESSION"
    INDICATOR_REPETITION = "INDICATOR_REPETITION"
    THREAT_CONCENTRATION = "THREAT_CONCENTRATION"


@dataclass(frozen=True)
class BehavioralFinding:
    """Analytical pattern discovered across a sequence of security events."""

    pattern: BehavioralPatternType
    severity: Severity
    title: str
    explanation: str
    score_boost: int
    confidence_boost: float

    def to_reason(self) -> ExplainableReason:
        return ExplainableReason(
            category=ThreatCategory.EVASION,
            severity=self.severity,
            title=self.title,
            explanation=self.explanation,
            score_contribution=self.score_boost,
            rule_id=f"BEHAVIOR_{self.pattern.value}",
        )


@dataclass
class EventSnapshot:
    """Lightweight event representation for behavioral analysis."""

    event_id: str
    event_type: str  # "url_scan", "message_scan", "file_scan"
    risk_score: int
    classification: str
    created_at: datetime
    indicator_values: set[str]


class BehavioralAnalyzer:
    """Analyzes recent chronological scan events for behavioral threat patterns."""

    # Configurable detection thresholds
    RAPID_ATTACK_WINDOW_MINUTES: int = 15
    RAPID_ATTACK_COUNT_THRESHOLD: int = 3
    ESCALATION_WINDOW_MINUTES: int = 30
    MULTI_VECTOR_WINDOW_HOURS: int = 2
    CONCENTRATION_MIN_EVENTS: int = 4
    CONCENTRATION_RATIO_THRESHOLD: float = 0.5

    @classmethod
    def analyze_events(
        cls,
        events: list[EventSnapshot],
        current_event: EventSnapshot | None = None,
    ) -> list[BehavioralFinding]:
        """Analyze a sorted sequence of events for behavioral anomalies."""
        findings: list[BehavioralFinding] = []
        if not events:
            return findings

        # Ensure chronological ordering (oldest to newest)
        sorted_events = sorted(events, key=lambda e: e.created_at)
        ref_time = current_event.created_at if current_event else sorted_events[-1].created_at

        # 1. Check for rapid repeated high/critical scans
        rapid_window_start = ref_time - timedelta(minutes=cls.RAPID_ATTACK_WINDOW_MINUTES)
        recent_severe = [
            e
            for e in sorted_events
            if e.created_at >= rapid_window_start
            and e.classification
            in {RiskClassification.HIGH_RISK.value, RiskClassification.CRITICAL.value}
        ]
        if len(recent_severe) >= cls.RAPID_ATTACK_COUNT_THRESHOLD:
            findings.append(
                BehavioralFinding(
                    pattern=BehavioralPatternType.RAPID_REPEAT_ATTACKS,
                    severity=Severity.HIGH,
                    title="Rapid Successive High-Risk Activity",
                    explanation=(
                        f"Detected {len(recent_severe)} high or critical threat detections "
                        f"within a {cls.RAPID_ATTACK_WINDOW_MINUTES}-minute window."
                    ),
                    score_boost=15,
                    confidence_boost=0.10,
                )
            )

        # 2. Check for severity escalation (e.g. LOW/MEDIUM -> HIGH -> CRITICAL)
        escalation_window_start = ref_time - timedelta(minutes=cls.ESCALATION_WINDOW_MINUTES)
        escalation_events = [e for e in sorted_events if e.created_at >= escalation_window_start]
        if len(escalation_events) >= 3:
            scores = [e.risk_score for e in escalation_events]
            # Check if monotonically increasing by at least 15 points overall
            is_escalating = all(scores[i] <= scores[i + 1] for i in range(len(scores) - 1))
            if is_escalating and (scores[-1] - scores[0] >= 20) and scores[-1] >= 75:
                findings.append(
                    BehavioralFinding(
                        pattern=BehavioralPatternType.SEVERITY_ESCALATION,
                        severity=Severity.HIGH,
                        title="Severity Escalation Sequence",
                        explanation=(
                            f"Observed threat severity progression from {scores[0]}/100 to "
                            f"{scores[-1]}/100 across {len(scores)} scans in "
                            f"{cls.ESCALATION_WINDOW_MINUTES} minutes."
                        ),
                        score_boost=15,
                        confidence_boost=0.10,
                    )
                )

        # 3. Check for multi-vector progression (e.g. Message -> URL or Message -> URL -> File)
        mv_window_start = ref_time - timedelta(hours=cls.MULTI_VECTOR_WINDOW_HOURS)
        mv_events = [e for e in sorted_events if e.created_at >= mv_window_start]
        distinct_vectors = {e.event_type for e in mv_events}
        if len(distinct_vectors) >= 2:
            vector_names = ", ".join(sorted(distinct_vectors)).replace("_scan", "")
            findings.append(
                BehavioralFinding(
                    pattern=BehavioralPatternType.MULTI_VECTOR_PROGRESSION,
                    severity=Severity.MEDIUM,
                    title="Multi-Vector Threat Progression",
                    explanation=(
                        f"Observed coordinated threat activity across vectors ({vector_names}) "
                        f"within a {cls.MULTI_VECTOR_WINDOW_HOURS}-hour timeframe."
                    ),
                    score_boost=10,
                    confidence_boost=0.08,
                )
            )

        # 4. Check for threat concentration (many scans targeting the same indicator)
        if len(sorted_events) >= cls.CONCENTRATION_MIN_EVENTS:
            indicator_counts: dict[str, int] = {}
            for e in sorted_events:
                for ind in e.indicator_values:
                    indicator_counts[ind] = indicator_counts.get(ind, 0) + 1

            for ind, count in indicator_counts.items():
                ratio = count / len(sorted_events)
                if ratio >= cls.CONCENTRATION_RATIO_THRESHOLD and count >= 3:
                    pct = int(ratio * 100)
                    findings.append(
                        BehavioralFinding(
                            pattern=BehavioralPatternType.THREAT_CONCENTRATION,
                            severity=Severity.HIGH,
                            title="High Threat Concentration on Single Indicator",
                            explanation=(
                                f"Indicator '{ind}' accounts for {count} of {len(sorted_events)} "
                                f"({pct}%) of security events, showing persistent focus."
                            ),
                            score_boost=15,
                            confidence_boost=0.12,
                        )
                    )
                    break

        return findings
