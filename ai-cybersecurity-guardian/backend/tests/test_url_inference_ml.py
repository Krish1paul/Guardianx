"""Tests for ml/inference/url_inference.py — ML engine.

Verifies:
- ML engine loads and produces analyzer_version="ml-v1"
- risk_score in [0, 100]
- Adversarial URL scores higher than benign URL
- Deterministic: same URL → same score
- Fallback: missing model → returns rule-v1 result (not ml-v1)
- Fallback: corrupt model file → returns rule-v1 result
- Fallback: wrong feature schema version → returns rule-v1 result
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ml.features import url_features  # noqa: E402

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

MODEL_DIR = os.path.join(_PROJECT_ROOT, "ml", "models", "url_model_v1")
MODEL_EXISTS = (
    os.path.isfile(os.path.join(MODEL_DIR, "model.pkl"))
    and os.path.isfile(os.path.join(MODEL_DIR, "metadata.json"))
    and os.path.isfile(os.path.join(MODEL_DIR, "feature_schema.json"))
)


# ---------------------------------------------------------------------------
# Tests that require a trained model artifact
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not MODEL_EXISTS, reason="ML model artifact not found")
class TestMLInferenceWithModel:
    def _engine(self) -> Any:
        """Return a fresh URLInferenceEngine with the module state reset."""
        import ml.inference.url_inference as mod
        mod._state = None  # force reload
        from ml.inference.url_inference import URLInferenceEngine
        return URLInferenceEngine()

    def test_analyzer_version_is_ml_v1(self) -> None:
        engine = self._engine()
        f = url_features.extract("https://example.com/")
        result = engine.run(f)
        assert result.analyzer_version == "ml-v1"

    def test_score_in_valid_range(self) -> None:
        engine = self._engine()
        for url in [
            "https://example.com/",
            "http://192.168.1.1/login",
            "https://xn--pypal-4ve.com/verify",
            "https://a.b.c.evil.xyz/login?password=steal",
        ]:
            f = url_features.extract(url)
            result = engine.run(f)
            assert 0 <= result.score <= 100, f"Score out of range for {url}: {result.score}"

    def test_adversarial_scores_higher_than_benign(self) -> None:
        engine = self._engine()
        benign = url_features.extract("https://example.com/")
        adversarial = url_features.extract("http://192.168.1.1/login")
        r_benign = engine.run(benign)
        r_adversarial = engine.run(adversarial)
        assert r_adversarial.score > r_benign.score, (
            f"Adversarial ({r_adversarial.score}) must score > benign ({r_benign.score})"
        )

    def test_deterministic_same_url_same_score(self) -> None:
        engine = self._engine()
        url = "https://suspicious.xyz/login?token=abc"
        f = url_features.extract(url)
        r1 = engine.run(f)
        r2 = engine.run(f)
        assert r1.score == r2.score
        assert r1.classification == r2.classification

    def test_classification_matches_score(self) -> None:
        from ml.features.url_risk_engine import RiskClassification

        engine = self._engine()
        for url in ["https://example.com/", "http://192.168.1.1/login"]:
            f = url_features.extract(url)
            result = engine.run(f)
            score = result.score
            cls = result.classification
            if score >= 75:
                assert cls == RiskClassification.CRITICAL
            elif score >= 50:
                assert cls == RiskClassification.HIGH_RISK
            elif score >= 25:
                assert cls == RiskClassification.MEDIUM_RISK
            else:
                assert cls == RiskClassification.LOW_RISK

    def test_reasons_is_list(self) -> None:
        engine = self._engine()
        f = url_features.extract("https://example.com/")
        result = engine.run(f)
        assert isinstance(result.reasons, list)

    def test_high_risk_url_has_non_negative_score(self) -> None:
        engine = self._engine()
        f = url_features.extract("http://192.168.1.1/login")
        result = engine.run(f)
        assert result.score >= 0


# ---------------------------------------------------------------------------
# Fallback tests (model missing, corrupt, schema mismatch)
# ---------------------------------------------------------------------------


class TestMLInferenceFallback:
    """Tests for the fallback-to-rule-v1 behaviour."""

    def _run_with_missing_model(self, url: str) -> Any:
        """Run inference with _state forced to a non-loaded state."""
        import ml.inference.url_inference as mod
        original_state = mod._state
        # Create a fake state with loaded=False
        fake_state = mod._MLModelState.__new__(mod._MLModelState)
        fake_state.model = None
        fake_state.loaded = False
        fake_state.threshold = 0.5
        fake_state.explainer = None
        fake_state.metadata = {}
        mod._state = fake_state

        try:
            from ml.inference.url_inference import URLInferenceEngine
            engine = URLInferenceEngine()
            f = url_features.extract(url)
            return engine.run(f)
        finally:
            mod._state = original_state

    def test_fallback_returns_rule_v1_not_ml_v1(self) -> None:
        result = self._run_with_missing_model("https://example.com/")
        assert result.analyzer_version == "rule-v1", (
            f"Fallback must return rule-v1, got {result.analyzer_version}"
        )

    def test_fallback_still_returns_valid_score(self) -> None:
        result = self._run_with_missing_model("https://example.com/")
        assert 0 <= result.score <= 100

    def test_fallback_on_missing_model_file(self, tmp_path: object) -> None:
        """Loading from an empty directory should trigger fallback."""
        import ml.inference.url_inference as mod
        original_state = mod._state
        mod._state = None

        original_dir = mod._MODEL_DIR
        original_pkl = mod._MODEL_PKL
        original_meta = mod._METADATA_JSON
        original_schema = mod._SCHEMA_JSON

        # Point to an empty temp dir
        mod._MODEL_DIR = str(tmp_path)
        mod._MODEL_PKL = os.path.join(str(tmp_path), "model.pkl")
        mod._METADATA_JSON = os.path.join(str(tmp_path), "metadata.json")
        mod._SCHEMA_JSON = os.path.join(str(tmp_path), "feature_schema.json")

        try:
            from ml.inference.url_inference import URLInferenceEngine
            engine = URLInferenceEngine()
            f = url_features.extract("https://example.com/")
            result = engine.run(f)
            assert result.analyzer_version == "rule-v1", (
                "Missing model artifact must fall back to rule-v1"
            )
        finally:
            mod._state = original_state
            mod._MODEL_DIR = original_dir
            mod._MODEL_PKL = original_pkl
            mod._METADATA_JSON = original_meta
            mod._SCHEMA_JSON = original_schema

    def test_fallback_on_wrong_schema_version(self, tmp_path: object) -> None:
        """Schema version mismatch must trigger fallback."""
        import ml.inference.url_inference as mod
        original_state = mod._state

        # Write a schema with wrong version
        schema = {
            "feature_schema_version": "WRONG_VERSION",
            "feature_count": 1,
            "feature_names": ["x"],
        }
        schema_path = os.path.join(str(tmp_path), "feature_schema.json")
        with open(schema_path, "w") as f:
            json.dump(schema, f)

        meta = {"classification_threshold": 0.5}
        meta_path = os.path.join(str(tmp_path), "metadata.json")
        with open(meta_path, "w") as f:
            json.dump(meta, f)

        pkl_path = os.path.join(str(tmp_path), "model.pkl")
        with open(pkl_path, "w") as f:
            f.write("not a valid pickle")

        mod._state = None
        original_dir = mod._MODEL_DIR
        original_pkl = mod._MODEL_PKL
        original_meta = mod._METADATA_JSON
        original_schema = mod._SCHEMA_JSON

        mod._MODEL_DIR = str(tmp_path)
        mod._MODEL_PKL = pkl_path
        mod._METADATA_JSON = meta_path
        mod._SCHEMA_JSON = schema_path

        try:
            from ml.inference.url_inference import URLInferenceEngine
            engine = URLInferenceEngine()
            f = url_features.extract("https://example.com/")
            result = engine.run(f)
            assert result.analyzer_version == "rule-v1"
        finally:
            mod._state = original_state
            mod._MODEL_DIR = original_dir
            mod._MODEL_PKL = original_pkl
            mod._METADATA_JSON = original_meta
            mod._SCHEMA_JSON = original_schema
