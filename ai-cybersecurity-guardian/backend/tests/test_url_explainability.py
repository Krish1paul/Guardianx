"""Tests for ml/inference/url_explainer.py — explainability.

Verifies:
- URLExplainer initializes correctly with and without importances
- explain() returns a list of RiskReason objects
- All reasons have valid code, severity, message
- High-probability adversarial URL generates reasons
- Low-probability benign URL returns empty reasons
- from_pipeline() extracts importances from RF, LR
- Duplicate reason codes are deduplicated
"""

from __future__ import annotations

import os
import sys

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from ml.features import url_features  # noqa: E402
from ml.features.url_feature_vector import FEATURE_COUNT  # noqa: E402
from ml.features.url_risk_engine import ReasonCode, Severity  # noqa: E402
from ml.inference.url_explainer import URLExplainer  # noqa: E402


def _make_trained_pipeline(model_cls: type, n: int = 50, seed: int = 42) -> Pipeline:
    """Train a small pipeline on dummy data."""
    rng = np.random.RandomState(seed)
    x = rng.randn(n, FEATURE_COUNT)  # noqa: N806 — ML convention
    y = [0] * (n // 2) + [1] * (n // 2)
    kwargs = {"random_state": seed} if hasattr(model_cls, "random_state") else {}
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", model_cls(**kwargs)),
    ])
    pipeline.fit(x, y)
    return pipeline


class TestURLExplainerInit:
    def test_init_without_importances_uses_uniform(self) -> None:
        explainer = URLExplainer()
        assert len(explainer._importances) == FEATURE_COUNT
        # Uniform: all equal
        val = explainer._importances[0]
        assert all(abs(v - val) < 1e-10 for v in explainer._importances)

    def test_init_with_importances(self) -> None:
        importances = [0.0] * FEATURE_COUNT
        importances[0] = 1.0
        explainer = URLExplainer(importances)
        assert explainer._importances == importances

    def test_wrong_length_raises(self) -> None:
        with pytest.raises(ValueError, match="feature_importances length"):
            URLExplainer([1.0, 2.0])  # too short


class TestFromPipeline:
    def test_from_rf_pipeline(self) -> None:
        pipeline = _make_trained_pipeline(RandomForestClassifier)
        explainer = URLExplainer.from_pipeline(pipeline)
        assert len(explainer._importances) == FEATURE_COUNT
        assert all(v >= 0.0 for v in explainer._importances)

    def test_from_lr_pipeline(self) -> None:
        pipeline = _make_trained_pipeline(LogisticRegression)
        explainer = URLExplainer.from_pipeline(pipeline)
        assert len(explainer._importances) == FEATURE_COUNT

    def test_importances_sum_to_roughly_one_for_rf(self) -> None:
        pipeline = _make_trained_pipeline(RandomForestClassifier)
        explainer = URLExplainer.from_pipeline(pipeline)
        total = sum(explainer._importances)
        assert abs(total - 1.0) < 0.01


class TestExplain:
    def test_returns_list(self) -> None:
        explainer = URLExplainer()
        f = url_features.extract("https://example.com/")
        reasons = explainer.explain(f, probability=0.9)
        assert isinstance(reasons, list)

    def test_low_probability_returns_empty(self) -> None:
        explainer = URLExplainer()
        f = url_features.extract("https://example.com/")
        reasons = explainer.explain(f, probability=0.10)
        assert reasons == []

    def test_high_probability_adversarial_has_reasons(self) -> None:
        # Give high importance to is_ip_address to force a reason
        from ml.features.url_feature_vector import FEATURE_NAMES

        importances = [0.0] * FEATURE_COUNT
        idx = FEATURE_NAMES.index("is_ip_address")
        importances[idx] = 1.0
        explainer = URLExplainer(importances)
        f = url_features.extract("http://192.168.1.1/login")
        reasons = explainer.explain(f, probability=0.9)
        # is_ip_address is True for this URL, so should produce a reason
        assert len(reasons) >= 1

    def test_all_reasons_have_valid_code(self) -> None:
        importances = [1.0 / FEATURE_COUNT] * FEATURE_COUNT
        explainer = URLExplainer(importances)
        f = url_features.extract("http://192.168.1.1/login")
        reasons = explainer.explain(f, probability=0.9)
        for r in reasons:
            assert isinstance(r.code, ReasonCode)

    def test_all_reasons_have_valid_severity(self) -> None:
        importances = [1.0 / FEATURE_COUNT] * FEATURE_COUNT
        explainer = URLExplainer(importances)
        f = url_features.extract("http://user:pass@192.168.1.1/login")
        reasons = explainer.explain(f, probability=0.9)
        for r in reasons:
            assert isinstance(r.severity, Severity)

    def test_all_reasons_have_non_empty_message(self) -> None:
        importances = [1.0 / FEATURE_COUNT] * FEATURE_COUNT
        explainer = URLExplainer(importances)
        f = url_features.extract("http://user:pass@192.168.1.1/login")
        reasons = explainer.explain(f, probability=0.9)
        for r in reasons:
            assert isinstance(r.message, str)
            assert len(r.message) > 0

    def test_no_duplicate_reason_codes(self) -> None:
        importances = [1.0 / FEATURE_COUNT] * FEATURE_COUNT
        explainer = URLExplainer(importances)
        f = url_features.extract("http://192.168.1.1/login")
        reasons = explainer.explain(f, probability=0.9)
        codes = [r.code for r in reasons]
        assert len(codes) == len(set(codes)), "Duplicate ReasonCodes found"

    def test_benign_url_low_risk_no_reasons(self) -> None:
        importances = [0.0] * FEATURE_COUNT  # all zero = no reasons
        explainer = URLExplainer(importances)
        f = url_features.extract("https://example.com/")
        reasons = explainer.explain(f, probability=0.05)
        assert reasons == []

    def test_score_contribution_is_non_negative(self) -> None:
        importances = [1.0 / FEATURE_COUNT] * FEATURE_COUNT
        explainer = URLExplainer(importances)
        f = url_features.extract("http://192.168.1.1/login")
        reasons = explainer.explain(f, probability=0.9)
        for r in reasons:
            assert r.score_contribution >= 0
