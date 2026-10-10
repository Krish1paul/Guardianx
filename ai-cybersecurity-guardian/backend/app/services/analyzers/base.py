"""Base analyzer abstraction — M7 Multi-Vector Architecture.

Defines the common interface and normalized result contract for all threat analyzers:
- URLAnalyzer
- MessageAnalyzer
- FileAnalyzer
"""

from __future__ import annotations

import abc
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Generic, TypeVar

from app.schemas.unified_analysis import ExplainableReason
from app.schemas.url_analysis import RiskClassification

TInput = TypeVar("TInput")
TOutput = TypeVar("TOutput")


@dataclass(frozen=True)
class NormalizedAnalysisResult:
    """Normalized threat assessment across all vectors."""

    id: uuid.UUID
    analyzer_type: str  # "url", "message", "file"
    risk_score: int  # [0, 100]
    classification: RiskClassification
    confidence: float  # [0.0, 1.0]
    reasons: list[ExplainableReason]
    extracted_features: dict[str, Any]
    analyzer_version: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    processing_metadata: dict[str, Any] = field(default_factory=dict)


class BaseAnalyzer(abc.ABC, Generic[TInput, TOutput]):
    """Abstract base class for all threat analyzers."""

    @property
    @abc.abstractmethod
    def analyzer_type(self) -> str:
        """Type identifier: 'url', 'message', 'file'."""

    @property
    @abc.abstractmethod
    def analyzer_version(self) -> str:
        """Version identifier of this analyzer implementation."""

    @abc.abstractmethod
    def analyze(self, input_data: TInput, user_id: uuid.UUID) -> TOutput:
        """Execute threat analysis and persist scan record."""
