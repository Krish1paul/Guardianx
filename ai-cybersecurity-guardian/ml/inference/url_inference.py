"""URL inference engine — M3 (ML-powered).

This module replaces the M2 rule-based stub with a trained ML classifier while
preserving the exact public interface:

    URLInferenceEngine.run(features: URLFeatures) -> URLRiskResult

No caller needs to change.  The ``analyzer_version`` field on the returned
``URLRiskResult`` distinguishes M3 output (``"ml-v1"``) from historical M2
output (``"rule-v1"``).

Fallback strategy
-----------------
If the ML model artifact is missing or corrupted at import time, the engine
**falls back** to the M2 deterministic rule engine.  The fallback result uses
``analyzer_version="rule-v1"`` — it is NEVER labelled ``"ml-v1"``.  A WARNING
is logged so the operational state is visible.

This is Option B from the implementation plan: explicit, logged fallback —
no silent mislabelling.

Risk score mapping
------------------
The ML model outputs a probability P(malicious) in [0, 1].

    risk_score = round(probability * 100)    → [0, 100]

Classification thresholds (unchanged from M2):

    0  – 24  →  LOW_RISK
    25 – 49  →  MEDIUM_RISK
    50 – 74  →  HIGH_RISK
    75 – 100 →  CRITICAL

The probability-to-score conversion and the classification thresholds are
applied here — not inside the model — keeping the model output (probability)
separate from the presentation layer (score / classification).

Model confidence
----------------
The engine does NOT claim certainty.  The probability is presented as a
model estimate (not a guarantee).  When the probability is near the decision
boundary (threshold ± 0.10), a ``near_threshold`` reason is included.

Security guarantees
-------------------
- No network requests are made during inference.
- The model artifact is loaded from a fixed trusted path.  No user-supplied
  paths are accepted.
- Pickle loading is restricted to the project model directory.
- If the feature schema version stored in the metadata does not match the
  current ``FEATURE_SCHEMA_VERSION``, the engine falls back to rule-v1.

Upgrade notes (M4+)
-------------------
To replace the model:
1. Place new artifact in ``ml/models/url_model_v1/`` (or a new versioned dir).
2. Update ``metadata.json`` with the new model version.
3. Restart the application — the engine is a module-level singleton.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Path setup — make ml/ and backend/ importable
# ---------------------------------------------------------------------------

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
_BACKEND_ROOT = os.path.join(_PROJECT_ROOT, "backend")
for _p in (_PROJECT_ROOT, _BACKEND_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from ml.features.url_feature_vector import (  # noqa: E402
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    features_to_vector,
)
from ml.features.url_features import URLFeatures  # noqa: E402
from ml.features.url_risk_engine import (  # noqa: E402
    ReasonCode,
    RiskClassification,
    RiskReason,
    Severity,
    URLRiskEngine,
    URLRiskResult,
)
from ml.inference.url_explainer import URLExplainer  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

URL_MODEL_VERSION: str = "ml-v1"

#: Trusted model directory — only artifacts from here are loaded.
_MODEL_DIR: str = os.path.join(_PROJECT_ROOT, "ml", "models", "url_model_v1")
_MODEL_PKL: str = os.path.join(_MODEL_DIR, "model.pkl")
_METADATA_JSON: str = os.path.join(_MODEL_DIR, "metadata.json")
_SCHEMA_JSON: str = os.path.join(_MODEL_DIR, "feature_schema.json")

# Probability thresholds for classification (same as M2 score thresholds)
_SCORE_THRESHOLDS = [
    (75, RiskClassification.CRITICAL),
    (50, RiskClassification.HIGH_RISK),
    (25, RiskClassification.MEDIUM_RISK),
    (0,  RiskClassification.LOW_RISK),
]

# Near-threshold band (± this value around the decision boundary)
_NEAR_THRESHOLD_BAND: float = 0.10

# ---------------------------------------------------------------------------
# Score / classification helpers
# ---------------------------------------------------------------------------


def _prob_to_score(probability: float) -> int:
    """Convert malicious probability [0,1] to risk score [0,100]."""
    return max(0, min(100, round(probability * 100)))


def _classify_score(score: int) -> RiskClassification:
    """Map risk score to classification tier (same thresholds as M2)."""
    for threshold, classification in _SCORE_THRESHOLDS:
        if score >= threshold:
            return classification
    return RiskClassification.LOW_RISK


# ---------------------------------------------------------------------------
# Model loader (module-level singleton)
# ---------------------------------------------------------------------------


class _MLModelState:
    """Holds the loaded ML model and its metadata.  Loaded once at import."""

    def __init__(self) -> None:
        self.model: Any = None
        self.metadata: dict[str, Any] = {}
        self.threshold: float = 0.50
        self.explainer: URLExplainer | None = None
        self.loaded: bool = False
        self._load()

    def _load(self) -> None:
        """Attempt to load the ML model artifact.

        On any failure, sets ``self.loaded = False`` and logs a warning.
        The engine will use the rule-v1 fallback for all requests.
        """
        # ── Validate trusted path ────────────────────────────────────────────
        real_model_dir = os.path.realpath(_MODEL_DIR)
        real_project_root = os.path.realpath(_PROJECT_ROOT)
        if not real_model_dir.startswith(real_project_root):
            logger.warning(
                "ML model directory %r is outside the project root — "
                "refusing to load.  Falling back to rule-v1.",
                _MODEL_DIR,
            )
            return

        # ── Check artifact presence ──────────────────────────────────────────
        for artifact_path in (_MODEL_PKL, _METADATA_JSON, _SCHEMA_JSON):
            if not os.path.isfile(artifact_path):
                logger.warning(
                    "ML model artifact missing: %r.  Falling back to rule-v1.", artifact_path
                )
                return

        # ── Validate feature schema ──────────────────────────────────────────
        try:
            with open(_SCHEMA_JSON) as f:
                schema: dict[str, Any] = json.load(f)
            saved_version: str = schema.get("feature_schema_version", "")
            if saved_version != FEATURE_SCHEMA_VERSION:
                logger.warning(
                    "Feature schema version mismatch: model has %r, code expects %r.  "
                    "Falling back to rule-v1.",
                    saved_version,
                    FEATURE_SCHEMA_VERSION,
                )
                return
            saved_names: list[str] = schema.get("feature_names", [])
            if saved_names != FEATURE_NAMES:
                logger.warning(
                    "Feature name list mismatch between model and code.  "
                    "Falling back to rule-v1."
                )
                return
        except Exception as exc:
            logger.warning("Failed to read feature schema: %s.  Falling back to rule-v1.", exc)
            return

        # ── Load metadata ────────────────────────────────────────────────────
        try:
            with open(_METADATA_JSON) as f:
                self.metadata = json.load(f)
            self.threshold = float(self.metadata.get("classification_threshold", 0.50))
        except Exception as exc:
            logger.warning("Failed to read metadata.json: %s.  Falling back to rule-v1.", exc)
            return

        # ── Load model ───────────────────────────────────────────────────────
        try:
            import joblib  # lazy — not a hard import-time dependency
            self.model = joblib.load(_MODEL_PKL)
        except Exception as exc:
            logger.warning("Failed to load model.pkl: %s.  Falling back to rule-v1.", exc)
            self.model = None
            return

        # ── Build explainer ──────────────────────────────────────────────────
        try:
            self.explainer = URLExplainer.from_pipeline(self.model)
        except Exception as exc:
            logger.warning("Failed to build explainer: %s.  Reasons will be unavailable.", exc)
            self.explainer = URLExplainer()  # uniform fallback

        self.loaded = True
        model_type = self.metadata.get("model_type", "unknown")
        logger.info(
            "ML model loaded: version=%s  type=%s  threshold=%.2f",
            URL_MODEL_VERSION, model_type, self.threshold,
        )


# Module-level singleton — loaded once when the module is imported.
_state: _MLModelState | None = None
# Rule engine kept for fallback.
_rule_engine = URLRiskEngine()


def _get_state() -> _MLModelState:
    global _state
    if _state is None:
        _state = _MLModelState()
    return _state


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


class URLInferenceEngine:
    """Inference engine for URL risk scoring — M3 ML implementation.

    Usage::

        engine = URLInferenceEngine()
        result = engine.run(features)

    The returned ``URLRiskResult`` carries ``analyzer_version="ml-v1"``
    when ML inference succeeded, or ``"rule-v1"`` if the fallback fired.

    Thread safety
    -------------
    Stateless per call.  The module-level ``_state`` singleton is loaded
    once and is read-only during inference — safe for concurrent requests.
    """

    def run(self, features: URLFeatures) -> URLRiskResult:
        """Score URL risk given extracted features.

        Parameters
        ----------
        features:
            Pre-computed ``URLFeatures`` from ``url_features.extract()``.

        Returns
        -------
        URLRiskResult:
            Risk score [0–100], classification tier, explainable reasons,
            and ``analyzer_version``.

        Notes
        -----
        If the ML model is unavailable, falls back to rule-v1 transparently.
        The ``analyzer_version`` field reflects which engine produced the result.
        """
        state = _get_state()

        # ── ML path ──────────────────────────────────────────────────────────
        if state.loaded and state.model is not None:
            return self._ml_inference(features, state)

        # ── Fallback: rule-v1 ─────────────────────────────────────────────────
        return _rule_engine.score(features)

    def _ml_inference(
        self,
        features: URLFeatures,
        state: _MLModelState,
    ) -> URLRiskResult:
        """Run ML inference and build URLRiskResult."""
        import numpy as np  # lazy — training-time dep not always needed at startup

        # Convert features to numeric vector
        vector = features_to_vector(features)
        X = np.array([vector])

        # Predict probability P(malicious)
        probas = state.model.predict_proba(X)
        probability: float = float(probas[0, 1])

        # Risk score: P × 100, clamped to [0, 100]
        risk_score = _prob_to_score(probability)
        classification = _classify_score(risk_score)

        # Generate explainable reasons
        reasons: list[RiskReason] = []
        if state.explainer is not None:
            reasons = state.explainer.explain(features, probability)

        # Near-threshold notice
        threshold = state.threshold
        if abs(probability - threshold) <= _NEAR_THRESHOLD_BAND:
            reasons.append(
                RiskReason(
                    code=ReasonCode.SUSPICIOUS_KEYWORD,  # closest generic code
                    severity=Severity.LOW,
                    message=(
                        f"Model probability ({probability:.2f}) is near the decision "
                        f"boundary ({threshold:.2f}) — classification confidence is moderate."
                    ),
                    score_contribution=0,
                )
            )

        return URLRiskResult(
            score=risk_score,
            classification=classification,
            reasons=reasons,
            analyzer_version=URL_MODEL_VERSION,
        )
