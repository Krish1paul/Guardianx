"""Message threat ML inference engine — M7.

Provides phishing probability estimation and explainability features.
Implements defense-in-depth model loading:
- Local trusted artifact path only.
- Cryptographic SHA-256 checksum verification against metadata.json.
- Graceful heuristic fallback if artifact is missing, corrupted, or tampered.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib  # type: ignore[import-untyped]

from ml.features.message_features import MessageFeatures

logger = logging.getLogger(__name__)

DEFAULT_MODEL_DIR = Path(__file__).resolve().parent.parent / "models" / "message_model_v1"


@dataclass(frozen=True)
class MessageInferenceResult:
    """Output from message threat inference."""

    phishing_probability: float  # [0.0, 1.0]
    confidence: float  # [0.0, 1.0]
    top_contributing_terms: list[tuple[str, float]] = field(default_factory=list)
    model_version: str = "message-v1"
    used_fallback: bool = False
    fallback_reason: str | None = None


class MessageInferenceEngine:
    """Safe inference engine for message classification."""

    def __init__(self, model_dir: Path | None = None) -> None:
        self.model_dir = model_dir or DEFAULT_MODEL_DIR
        self._pipeline: Any = None
        self._metadata: dict[str, Any] = {}
        self._load_status: str = "unloaded"
        self._load_error: str | None = None
        self._init_model()

    def _init_model(self) -> None:
        """Verify SHA-256 and load model artifact."""
        model_path = self.model_dir / "model.pkl"
        metadata_path = self.model_dir / "metadata.json"

        if not model_path.exists() or not metadata_path.exists():
            self._load_status = "missing"
            self._load_error = f"Model artifact missing in {self.model_dir}"
            logger.warning(self._load_error)
            return

        try:
            with open(metadata_path, encoding="utf-8") as f:
                self._metadata = json.load(f)

            expected_sha256 = self._metadata.get("model_sha256")
            if not expected_sha256:
                self._load_status = "invalid_metadata"
                self._load_error = "metadata.json missing model_sha256"
                logger.warning(self._load_error)
                return

            with open(model_path, "rb") as f:
                actual_sha256 = hashlib.sha256(f.read()).hexdigest()

            if actual_sha256 != expected_sha256:
                self._load_status = "integrity_failed"
                self._load_error = (
                    f"Model SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
                )
                logger.error(self._load_error)
                return

            # Deserialization only after integrity check passes
            self._pipeline = joblib.load(model_path)
            self._load_status = "loaded"
            logger.info("Message ML model v1 loaded successfully with verified SHA-256")
        except Exception as exc:
            self._load_status = "error"
            self._load_error = f"Failed to load message model: {type(exc).__name__} - {exc}"
            logger.warning(self._load_error)

    @property
    def is_ready(self) -> bool:
        return self._load_status == "loaded" and self._pipeline is not None

    def predict(
        self,
        message: str,
        subject: str | None = None,
        features: MessageFeatures | None = None,
    ) -> MessageInferenceResult:
        """Predict phishing probability for a message."""
        combined_text = f"{subject}\n{message}" if subject else message

        if not self.is_ready:
            return self._heuristic_fallback(features, fallback_reason=self._load_error)

        try:
            proba = float(self._pipeline.predict_proba([combined_text])[0][1])

            # Model confidence: distance from ambiguous 0.5 decision boundary
            # e.g., proba=0.95 -> distance 0.45 * 2 = 0.90 confidence
            # baseline confidence starts at 0.5
            confidence = round(0.5 + abs(proba - 0.5), 3)
            confidence = max(0.5, min(1.0, confidence))

            top_terms = self._explain_prediction(combined_text)

            return MessageInferenceResult(
                phishing_probability=round(proba, 4),
                confidence=confidence,
                top_contributing_terms=top_terms,
                model_version=self._metadata.get("model_version", "message-v1"),
                used_fallback=False,
            )
        except Exception as exc:
            logger.warning("Inference execution failed, using fallback: %s", exc)
            return self._heuristic_fallback(features, fallback_reason=str(exc))

    def _explain_prediction(self, text: str, top_k: int = 5) -> list[tuple[str, float]]:
        """Extract top positive contributing terms for explainability."""
        if not self.is_ready:
            return []

        try:
            tfidf = self._pipeline.named_steps["tfidf"]
            clf = self._pipeline.named_steps["clf"]

            feature_names = tfidf.get_feature_names_out()
            coefficients = clf.coef_[0]

            # Transform single text
            X = tfidf.transform([text])
            nonzero_indices = X.nonzero()[1]

            contributions: list[tuple[str, float]] = []
            for idx in nonzero_indices:
                weight = float(coefficients[idx] * X[0, idx])
                if weight > 0:
                    contributions.append((str(feature_names[idx]), round(weight, 3)))

            # Sort descending by contribution
            contributions.sort(key=lambda x: x[1], reverse=True)
            return contributions[:top_k]
        except Exception:
            return []

    def _heuristic_fallback(
        self,
        features: MessageFeatures | None,
        fallback_reason: str | None = None,
    ) -> MessageInferenceResult:
        """Deterministic rule-based fallback when ML model is unavailable."""
        if features is None:
            return MessageInferenceResult(
                phishing_probability=0.2,
                confidence=0.5,
                used_fallback=True,
                fallback_reason=fallback_reason or "No features provided",
            )

        heuristic_score = 0.0
        if features.urgency_count > 0:
            heuristic_score += 0.25
        if features.credential_count > 0:
            heuristic_score += 0.35
        if features.financial_count > 0:
            heuristic_score += 0.25
        if features.suspension_count > 0:
            heuristic_score += 0.30
        if features.impersonation_count > 0:
            heuristic_score += 0.20
        if features.has_suspicious_subject:
            heuristic_score += 0.15
        if features.has_suspicious_sender:
            heuristic_score += 0.25

        prob = min(0.99, max(0.01, heuristic_score))
        return MessageInferenceResult(
            phishing_probability=round(prob, 4),
            confidence=0.75 if (features.urgency_count or features.credential_count) else 0.60,
            model_version="heuristic-rule-v1",
            used_fallback=True,
            fallback_reason=fallback_reason or "ML model unavailable",
        )
