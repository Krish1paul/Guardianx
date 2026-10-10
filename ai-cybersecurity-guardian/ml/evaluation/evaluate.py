"""URL model evaluation utilities — M3.

Provides a clean interface for computing classification metrics and selecting
an optimal probability threshold.

Cybersecurity metric priority
------------------------------
In URL threat detection, **false negatives** (malicious URL classified as benign)
are more dangerous than false positives.  Therefore:

- Primary selection criterion: **Recall** on the malicious class.
- Secondary criterion: **F1** (balances precision/recall).
- ``ROC-AUC`` is reported but not used as the primary selection criterion because
  it does not reflect operational threshold choice.

Threshold selection
-------------------
The default threshold of 0.5 is often not optimal for imbalanced security datasets.
``find_best_threshold()`` sweeps thresholds on the validation set and returns
the value that maximises recall while keeping precision above a minimum floor.

Security note
--------------
No network I/O.  Pure computation over numpy arrays and sklearn models.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class EvaluationResult:
    """Metrics for a single model evaluation.

    Attributes
    ----------
    threshold:
        Probability threshold used to binarize predictions.
    accuracy:
        Overall fraction of correct predictions.
    precision:
        Positive predictive value for the malicious class (label=1).
    recall:
        True positive rate for the malicious class (label=1).
    f1:
        Harmonic mean of precision and recall.
    roc_auc:
        Area under the ROC curve (threshold-independent).
    false_positive_rate:
        FP / (FP + TN) — benign URLs incorrectly flagged.
    false_negative_rate:
        FN / (FN + TP) — malicious URLs missed.
    confusion_matrix:
        2x2 matrix [[TN, FP], [FN, TP]].
    n_samples:
        Number of samples evaluated.
    """

    threshold: float
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: float
    false_positive_rate: float
    false_negative_rate: float
    confusion_matrix: list[list[int]] = field(default_factory=list)
    n_samples: int = 0

    def summary(self) -> str:
        """One-line human-readable summary."""
        return (
            f"threshold={self.threshold:.2f}  "
            f"precision={self.precision:.3f}  "
            f"recall={self.recall:.3f}  "
            f"f1={self.f1:.3f}  "
            f"roc_auc={self.roc_auc:.3f}  "
            f"FNR={self.false_negative_rate:.3f}  "
            f"FPR={self.false_positive_rate:.3f}  "
            f"n={self.n_samples}"
        )


# ---------------------------------------------------------------------------
# Core evaluation
# ---------------------------------------------------------------------------


def evaluate_model(
    model: object,
    X: list[list[float]],
    y: list[int],
    threshold: float = 0.5,
) -> EvaluationResult:
    """Evaluate a trained sklearn-compatible model.

    Parameters
    ----------
    model:
        A fitted sklearn Pipeline or classifier exposing ``predict_proba()``.
    X:
        Feature matrix as a list of float vectors.
    y:
        True binary labels (0 = benign, 1 = malicious).
    threshold:
        Decision threshold applied to ``predict_proba()[:, 1]``.

    Returns
    -------
    EvaluationResult:
        Full suite of metrics.

    Raises
    ------
    ValueError:
        If model does not expose ``predict_proba``.
    """
    if not hasattr(model, "predict_proba"):
        raise ValueError("Model must expose predict_proba() for threshold-based evaluation.")

    X_arr = np.array(X)
    y_arr = np.array(y)

    probas: np.ndarray = model.predict_proba(X_arr)[:, 1]  # type: ignore[attr-defined]
    preds = (probas >= threshold).astype(int)

    cm: np.ndarray = confusion_matrix(y_arr, preds, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    fpr = float(fp) / float(fp + tn) if (fp + tn) > 0 else 0.0
    fnr = float(fn) / float(fn + tp) if (fn + tp) > 0 else 0.0

    return EvaluationResult(
        threshold=threshold,
        accuracy=float(accuracy_score(y_arr, preds)),
        precision=float(precision_score(y_arr, preds, zero_division=0)),
        recall=float(recall_score(y_arr, preds, zero_division=0)),
        f1=float(f1_score(y_arr, preds, zero_division=0)),
        roc_auc=float(roc_auc_score(y_arr, probas)),
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        confusion_matrix=cm.tolist(),
        n_samples=len(y),
    )


def find_best_threshold(
    model: object,
    X_val: list[list[float]],
    y_val: list[int],
    min_precision: float = 0.50,
    sweep_steps: int = 41,
) -> float:
    """Find the threshold that maximises recall subject to minimum precision.

    Sweeps thresholds from 0.30 to 0.70 and returns the one with the highest
    recall where precision >= ``min_precision``.  Falls back to 0.50 if no
    threshold satisfies the precision constraint.

    Parameters
    ----------
    model:
        Fitted sklearn-compatible model with ``predict_proba()``.
    X_val:
        Validation feature matrix.
    y_val:
        Validation true labels.
    min_precision:
        Minimum acceptable precision for the malicious class.
    sweep_steps:
        Number of threshold values to evaluate between 0.30 and 0.70.

    Returns
    -------
    float:
        Selected threshold in [0.30, 0.70].
    """
    best_threshold = 0.50
    best_recall = -1.0

    thresholds = np.linspace(0.30, 0.70, sweep_steps)
    for t in thresholds:
        result = evaluate_model(model, X_val, y_val, threshold=float(t))
        if result.precision >= min_precision and result.recall > best_recall:
            best_recall = result.recall
            best_threshold = float(t)

    logger.info(
        "Best threshold=%.2f (recall=%.3f, min_precision=%.2f)",
        best_threshold, best_recall, min_precision,
    )
    return best_threshold
