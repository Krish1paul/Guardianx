"""Security Intelligence package — M8."""

from app.services.intelligence.behavioral_analyzer import (
    BehavioralAnalyzer,
    BehavioralFinding,
    BehavioralPatternType,
    EventSnapshot,
)
from app.services.intelligence.correlation_engine import CorrelationCandidate, CorrelationEngine
from app.services.intelligence.indicator_normalizer import (
    IndicatorNormalizer,
    IndicatorType,
    NormalizedIndicator,
)

__all__ = [
    "BehavioralAnalyzer",
    "BehavioralFinding",
    "BehavioralPatternType",
    "CorrelationCandidate",
    "CorrelationEngine",
    "EventSnapshot",
    "IndicatorNormalizer",
    "IndicatorType",
    "NormalizedIndicator",
]
