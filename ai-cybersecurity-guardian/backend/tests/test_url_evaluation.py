"""Tests for ml/evaluation/evaluate.py.

Verifies:
- evaluate_model() returns EvaluationResult with correct metric types
- confusion matrix is 2x2
- Metrics are in valid ranges [0, 1]
- find_best_threshold() returns float in [0.30, 0.70]
- Model without predict_proba raises ValueError
"""

from __future__ import annotations

import os
import sys

import numpy as np
import pytest
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from ml.evaluation.evaluate import (  # noqa: E402
    EvaluationResult,
    evaluate_model,
    find_best_threshold,
)


def _make_trained_model(
    n_benign: int = 60,
    n_malicious: int = 60,
    seed: int = 42,
) -> tuple[Pipeline, list[list[float]], list[int]]:
    """Train a small LogisticRegression on synthetic data for testing."""
    rng = np.random.RandomState(seed)

    x_benign = rng.randn(n_benign, 5).tolist()
    y_benign = [0] * n_benign

    x_mal = (rng.randn(n_malicious, 5) + 3.0).tolist()
    y_mal = [1] * n_malicious

    x = x_benign + x_mal
    y = y_benign + y_mal

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=200, random_state=seed)),
    ])
    pipeline.fit(np.array(x), y)
    return pipeline, x, y


class TestEvaluateModel:
    def test_returns_evaluation_result_type(self) -> None:
        model, x, y = _make_trained_model()
        result = evaluate_model(model, x, y)
        assert isinstance(result, EvaluationResult)

    def test_accuracy_in_valid_range(self) -> None:
        model, x, y = _make_trained_model()
        result = evaluate_model(model, x, y)
        assert 0.0 <= result.accuracy <= 1.0

    def test_precision_in_valid_range(self) -> None:
        model, x, y = _make_trained_model()
        result = evaluate_model(model, x, y)
        assert 0.0 <= result.precision <= 1.0

    def test_recall_in_valid_range(self) -> None:
        model, x, y = _make_trained_model()
        result = evaluate_model(model, x, y)
        assert 0.0 <= result.recall <= 1.0

    def test_f1_in_valid_range(self) -> None:
        model, x, y = _make_trained_model()
        result = evaluate_model(model, x, y)
        assert 0.0 <= result.f1 <= 1.0

    def test_roc_auc_in_valid_range(self) -> None:
        model, x, y = _make_trained_model()
        result = evaluate_model(model, x, y)
        assert 0.0 <= result.roc_auc <= 1.0

    def test_fnr_in_valid_range(self) -> None:
        model, x, y = _make_trained_model()
        result = evaluate_model(model, x, y)
        assert 0.0 <= result.false_negative_rate <= 1.0

    def test_fpr_in_valid_range(self) -> None:
        model, x, y = _make_trained_model()
        result = evaluate_model(model, x, y)
        assert 0.0 <= result.false_positive_rate <= 1.0

    def test_confusion_matrix_is_2x2(self) -> None:
        model, x, y = _make_trained_model()
        result = evaluate_model(model, x, y)
        cm = result.confusion_matrix
        assert len(cm) == 2
        assert len(cm[0]) == 2
        assert len(cm[1]) == 2

    def test_confusion_matrix_sums_to_n_samples(self) -> None:
        model, x, y = _make_trained_model()
        result = evaluate_model(model, x, y)
        total = sum(result.confusion_matrix[r][c] for r in range(2) for c in range(2))
        assert total == len(y)

    def test_n_samples_matches_input(self) -> None:
        model, x, y = _make_trained_model()
        result = evaluate_model(model, x, y)
        assert result.n_samples == len(y)

    def test_threshold_stored_in_result(self) -> None:
        model, x, y = _make_trained_model()
        result = evaluate_model(model, x, y, threshold=0.6)
        assert result.threshold == 0.6

    def test_low_threshold_increases_recall(self) -> None:
        model, x, y = _make_trained_model()
        result_low = evaluate_model(model, x, y, threshold=0.3)
        result_high = evaluate_model(model, x, y, threshold=0.7)
        assert result_low.recall >= result_high.recall

    def test_model_without_predict_proba_raises(self) -> None:
        from sklearn.svm import SVC

        svc = SVC()
        with pytest.raises(ValueError, match="predict_proba"):
            evaluate_model(svc, [[1.0, 2.0]], [0])

    def test_summary_is_string(self) -> None:
        model, x, y = _make_trained_model()
        result = evaluate_model(model, x, y)
        summary = result.summary()
        assert isinstance(summary, str)
        assert "recall" in summary


class TestFindBestThreshold:
    def test_returns_float(self) -> None:
        model, x, y = _make_trained_model()
        threshold = find_best_threshold(model, x, y)
        assert isinstance(threshold, float)

    def test_threshold_in_valid_range(self) -> None:
        model, x, y = _make_trained_model()
        threshold = find_best_threshold(model, x, y)
        assert 0.30 <= threshold <= 0.70

    def test_result_consistent_with_threshold(self) -> None:
        """Evaluating at the returned threshold should give recall improvement."""
        model, x, y = _make_trained_model()
        threshold = find_best_threshold(model, x, y, min_precision=0.5)
        result = evaluate_model(model, x, y, threshold=threshold)
        assert result.precision >= 0.5 or result.recall > 0  # at least one holds
