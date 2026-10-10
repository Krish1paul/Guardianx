"""URL threat model training pipeline — M3.

Usage
-----
Run from the project root (``ai-cybersecurity-guardian/``):

    python3 -m ml.training.train_url_model

    # Custom dataset:
    python3 -m ml.training.train_url_model \\
        --dataset ml/datasets/raw/phishtank_urls.csv \\
        --dataset-version phishtank_v1

This script:
1. Loads and validates the dataset.
2. Splits into train / validation / test (70/15/15, stratified, seed=42).
3. Builds numeric feature matrices via ``url_feature_vector``.
4. Trains Logistic Regression (baseline), Random Forest, and XGBoost
   (if importable).
5. Selects the best model by recall on the validation set (cybersecurity
   priority: minimise false negatives).
6. Evaluates the selected model on the held-out test set.
7. Saves model artifact, metadata.json, and feature_schema.json to
   ``ml/models/url_model_v1/``.

⚠️ SYNTHETIC FIXTURE WARNING
When run against ``ml/datasets/fixtures/sample_urls.csv``, the resulting
model is trained on synthetically generated URLs that mirror M2 rule logic.
The model will likely replicate rule behaviour rather than generalise.
Metrics on this fixture are NOT production-representative.

Model selection criterion
--------------------------
Primary:   highest Recall on malicious class (validation set)
Secondary: highest F1 (tie-break)
Rationale: False negatives (missed malicious URLs) are more dangerous than
           false positives (benign URLs flagged) in cybersecurity.

Security
--------
- No network requests.
- Model artifact saved only to the trusted project ``ml/models/`` directory.
- No user-controlled paths are accepted without validation.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# Path setup — make ml/ importable from project root
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
_BACKEND_ROOT = os.path.join(_PROJECT_ROOT, "backend")
for p in (_PROJECT_ROOT, _BACKEND_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

import joblib  # noqa: E402
import numpy as np  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.pipeline import Pipeline  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

from ml.evaluation.evaluate import EvaluationResult, evaluate_model, find_best_threshold  # noqa: E402
from ml.features import url_features as url_feat_mod  # noqa: E402
from ml.features.url_feature_vector import (  # noqa: E402
    FEATURE_COUNT,
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    features_to_vector,
)
from ml.preprocessing.url_dataset import DatasetSplit, load_and_split  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("ml.training")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODEL_VERSION = "ml-v1"
DEFAULT_DATASET = os.path.join(_PROJECT_ROOT, "ml", "datasets", "fixtures", "sample_urls.csv")
DEFAULT_DATASET_VERSION = "synthetic-fixture-v1"
MODEL_OUTPUT_DIR = os.path.join(_PROJECT_ROOT, "ml", "models", "url_model_v1")
SEED = 42

# ---------------------------------------------------------------------------
# XGBoost — optional dependency
# ---------------------------------------------------------------------------
_xgb_available = False
try:
    from xgboost import XGBClassifier  # type: ignore[import]
    _xgb_available = True
    logger.info("XGBoost available — will include in comparison")
except ImportError:
    logger.info("XGBoost not available — skipping (Random Forest is primary)")


# ---------------------------------------------------------------------------
# Feature matrix builder
# ---------------------------------------------------------------------------


def _build_matrix(split_partition: list[tuple[str, int]]) -> tuple[list[list[float]], list[int]]:
    """Convert url/label pairs to feature matrix and label vector."""
    X: list[list[float]] = []
    y: list[int] = []
    for url, label in split_partition:
        features = url_feat_mod.extract(url)
        X.append(features_to_vector(features))
        y.append(label)
    return X, y


# ---------------------------------------------------------------------------
# Model definitions
# ---------------------------------------------------------------------------


def _make_models() -> dict[str, Any]:
    """Return dict of model_name → unfitted sklearn Pipeline."""
    models: dict[str, Any] = {
        "LogisticRegression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(
                C=1.0,
                max_iter=1000,
                random_state=SEED,
                class_weight="balanced",
            )),
        ]),
        "RandomForest": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_leaf=2,
                random_state=SEED,
                class_weight="balanced",
                n_jobs=-1,
            )),
        ]),
    }
    if _xgb_available:
        models["XGBoost"] = Pipeline([
            ("scaler", StandardScaler()),
            ("clf", XGBClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.1,
                random_state=SEED,
                eval_metric="logloss",
                use_label_encoder=False,
            )),
        ])
    return models


# ---------------------------------------------------------------------------
# Model selection
# ---------------------------------------------------------------------------


def _select_best(
    results: dict[str, EvaluationResult],
) -> str:
    """Select the best model by recall, tie-broken by F1."""
    best_name = max(
        results,
        key=lambda name: (results[name].recall, results[name].f1),
    )
    logger.info(
        "Selected model: %s  (recall=%.3f, f1=%.3f)",
        best_name,
        results[best_name].recall,
        results[best_name].f1,
    )
    return best_name


# ---------------------------------------------------------------------------
# Save artifacts
# ---------------------------------------------------------------------------


def _save_artifacts(
    model: Any,
    threshold: float,
    val_result: EvaluationResult,
    test_result: EvaluationResult,
    model_name: str,
    split: DatasetSplit,
    dataset_path: str,
    dataset_version: str,
    is_synthetic: bool,
) -> None:
    """Save model.pkl, metadata.json, feature_schema.json."""
    os.makedirs(MODEL_OUTPUT_DIR, exist_ok=True)

    # model.pkl
    model_path = os.path.join(MODEL_OUTPUT_DIR, "model.pkl")
    joblib.dump(model, model_path)
    logger.info("Saved model artifact: %s", model_path)

    # feature_schema.json
    schema_path = os.path.join(MODEL_OUTPUT_DIR, "feature_schema.json")
    schema: dict[str, Any] = {
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_count": FEATURE_COUNT,
        "feature_names": FEATURE_NAMES,
    }
    with open(schema_path, "w") as f:
        json.dump(schema, f, indent=2)
    logger.info("Saved feature schema: %s", schema_path)

    # metadata.json
    training_note = (
        "SYNTHETIC FIXTURE ONLY — not production-representative. "
        "Metrics reflect synthetic data constructed from M2 rule logic. "
        "Replace with a real labeled dataset (PhishTank, ISCX, etc.) for production."
        if is_synthetic
        else "Trained on real dataset — see docs/ml-pipeline.md for details."
    )

    metadata: dict[str, Any] = {
        "model_version": MODEL_VERSION,
        "model_type": model_name,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_count": FEATURE_COUNT,
        "feature_names": FEATURE_NAMES,
        "classification_threshold": threshold,
        "random_seed": SEED,
        "dataset_path": os.path.basename(dataset_path),
        "dataset_version": dataset_version,
        "dataset_size": split.total_size,
        "train_size": split.train_size,
        "val_size": split.val_size,
        "test_size": split.test_size,
        "training_note": training_note,
        # Validation metrics
        "val_precision": round(val_result.precision, 4),
        "val_recall": round(val_result.recall, 4),
        "val_f1": round(val_result.f1, 4),
        "val_roc_auc": round(val_result.roc_auc, 4),
        "val_false_negative_rate": round(val_result.false_negative_rate, 4),
        "val_false_positive_rate": round(val_result.false_positive_rate, 4),
        # Test metrics
        "test_precision": round(test_result.precision, 4),
        "test_recall": round(test_result.recall, 4),
        "test_f1": round(test_result.f1, 4),
        "test_roc_auc": round(test_result.roc_auc, 4),
        "test_false_negative_rate": round(test_result.false_negative_rate, 4),
        "test_false_positive_rate": round(test_result.false_positive_rate, 4),
        "test_confusion_matrix": test_result.confusion_matrix,
        "test_accuracy": round(test_result.accuracy, 4),
        "training_date": datetime.now(UTC).isoformat(),
    }
    meta_path = os.path.join(MODEL_OUTPUT_DIR, "metadata.json")
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    logger.info("Saved metadata: %s", meta_path)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def _write_report(
    comparison: dict[str, EvaluationResult],
    selected: str,
    threshold: float,
    test_result: EvaluationResult,
    dataset_version: str,
    is_synthetic: bool,
    split: DatasetSplit,
) -> None:
    """Write a human-readable markdown evaluation report."""
    report_dir = os.path.join(_PROJECT_ROOT, "ml", "evaluation", "reports")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, "url_model_v1.md")

    synthetic_banner = (
        "\n> ⚠️ **SYNTHETIC FIXTURE** — Metrics below are NOT production-representative.\n"
        "> This dataset was generated from M2 rule logic.\n"
        "> Replace with a real labeled dataset for production.\n"
    ) if is_synthetic else ""

    lines: list[str] = [
        "# M3 URL Threat Classifier — Evaluation Report\n",
        f"Generated: {datetime.now(UTC).isoformat()}\n",
        synthetic_banner,
        "## Dataset\n",
        f"- **Version:** {dataset_version}",
        f"- **Train:** {split.train_size}",
        f"- **Validation:** {split.val_size}",
        f"- **Test:** {split.test_size}",
        f"- **Total:** {split.total_size}",
        "",
        "## Features\n",
        f"- Schema version: `{FEATURE_SCHEMA_VERSION}`",
        f"- Feature count: {FEATURE_COUNT}",
        f"- Features: {', '.join(FEATURE_NAMES)}",
        "",
        "## Model Comparison (Validation Set)\n",
        "| Model | Precision | Recall | F1 | ROC-AUC | FNR | FPR |",
        "|-------|-----------|--------|----|---------|-----|-----|",
    ]
    for name, r in comparison.items():
        marker = " **← selected**" if name == selected else ""
        lines.append(
            f"| {name}{marker} "
            f"| {r.precision:.3f} "
            f"| {r.recall:.3f} "
            f"| {r.f1:.3f} "
            f"| {r.roc_auc:.3f} "
            f"| {r.false_negative_rate:.3f} "
            f"| {r.false_positive_rate:.3f} |"
        )

    cm = test_result.confusion_matrix
    lines += [
        "",
        "## Selected Model\n",
        f"**{selected}**  (highest recall on validation, tie-break F1)\n",
        "## Classification Threshold\n",
        f"Threshold: **{threshold:.2f}**  ",
        "Optimised on validation set: maximise recall subject to precision ≥ 0.50.\n",
        "## Test Set Metrics\n",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Accuracy | {test_result.accuracy:.4f} |",
        f"| Precision | {test_result.precision:.4f} |",
        f"| Recall | {test_result.recall:.4f} |",
        f"| F1 | {test_result.f1:.4f} |",
        f"| ROC-AUC | {test_result.roc_auc:.4f} |",
        f"| False Negative Rate | {test_result.false_negative_rate:.4f} |",
        f"| False Positive Rate | {test_result.false_positive_rate:.4f} |",
        "",
        "## Confusion Matrix (Test Set)\n",
        "```",
        "               Predicted",
        "               Benign  Malicious",
        f"Actual Benign    {cm[0][0]:5d}  {cm[0][1]:5d}",
        f"Actual Malicious {cm[1][0]:5d}  {cm[1][1]:5d}",
        "```",
        "",
        "## Limitations\n",
        "- M3 is a **heuristic / statistical classifier** — not a complete phishing detector.",
        "- Does not fetch, crawl, or verify URLs.",
        "- Does not consult reputation databases.",
        "- Trained on features extractable from the URL string alone — misses all content signals.",
        "- Susceptible to adversarial URL construction that satisfies all extracted features.",
    ]
    if is_synthetic:
        lines += [
            "- **Synthetic data**: model may have learned to replicate M2 rule logic rather than",
            "  generalise to real-world phishing patterns.",
        ]
    lines += [
        "",
        "## Potential Bias Sources\n",
        "- TLD-based features assume English-language internet norms.",
        "- Keyword list reflects common English phishing terminology.",
        "- Benign baseline skews toward high-Alexa domains.",
        "",
        "## Known Failure Cases\n",
        "- Legitimate security-focused pages (e.g. `accounts.google.com/login`) may score medium.",
        "- Novel phishing domains that avoid known suspicious TLDs/keywords.",
        "- URL shorteners (the short URL itself may appear benign).",
    ]

    with open(report_path, "w") as f:
        f.write("\n".join(lines))
    logger.info("Evaluation report written to %s", report_path)


# ---------------------------------------------------------------------------
# Main training pipeline
# ---------------------------------------------------------------------------


def train(
    dataset_path: str = DEFAULT_DATASET,
    dataset_version: str = DEFAULT_DATASET_VERSION,
) -> None:
    """Run the full training pipeline."""
    is_synthetic = "synthetic" in dataset_version or "fixture" in dataset_version.lower()
    if is_synthetic:
        logger.warning(
            "Training on synthetic fixture — output model is NOT production-ready. "
            "Replace with a real labeled dataset for production deployment."
        )

    # 1. Load + split
    logger.info("Loading dataset: %s", dataset_path)
    split = load_and_split(dataset_path, seed=SEED)
    logger.info(
        "Dataset loaded: train=%d val=%d test=%d",
        split.train_size, split.val_size, split.test_size,
    )

    # 2. Build feature matrices
    logger.info("Building feature matrices …")
    X_train, y_train = _build_matrix(split.train)
    X_val, y_val = _build_matrix(split.val)
    X_test, y_test = _build_matrix(split.test)

    X_train_arr = np.array(X_train)
    X_val_arr = np.array(X_val)

    logger.info("Feature matrix shape: train=%s", X_train_arr.shape)

    # 3. Train all models
    models = _make_models()
    trained: dict[str, Any] = {}
    val_results: dict[str, EvaluationResult] = {}

    for name, pipeline in models.items():
        logger.info("Training %s …", name)
        pipeline.fit(X_train_arr, y_train)
        result = evaluate_model(pipeline, X_val, y_val, threshold=0.5)
        val_results[name] = result
        trained[name] = pipeline
        logger.info("  [val] %s", result.summary())

    # 4. Select best model
    best_name = _select_best(val_results)
    best_model = trained[best_name]

    # 5. Find optimal threshold on validation set
    threshold = find_best_threshold(best_model, X_val, y_val, min_precision=0.50)
    logger.info("Selected threshold: %.2f", threshold)

    # 6. Final evaluation on held-out test set
    test_result = evaluate_model(best_model, X_test, y_test, threshold=threshold)
    logger.info("[test] %s", test_result.summary())

    # 7. Save artifacts
    _save_artifacts(
        model=best_model,
        threshold=threshold,
        val_result=val_results[best_name],
        test_result=test_result,
        model_name=best_name,
        split=split,
        dataset_path=dataset_path,
        dataset_version=dataset_version,
        is_synthetic=is_synthetic,
    )

    # 8. Write report
    _write_report(
        comparison=val_results,
        selected=best_name,
        threshold=threshold,
        test_result=test_result,
        dataset_version=dataset_version,
        is_synthetic=is_synthetic,
        split=split,
    )

    logger.info("M3 training complete.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train M3 URL threat classifier")
    parser.add_argument(
        "--dataset",
        default=DEFAULT_DATASET,
        help="Path to CSV dataset (default: synthetic fixture)",
    )
    parser.add_argument(
        "--dataset-version",
        default=DEFAULT_DATASET_VERSION,
        help="Version label for dataset metadata (default: synthetic-fixture-v1)",
    )
    args = parser.parse_args()
    train(dataset_path=args.dataset, dataset_version=args.dataset_version)
