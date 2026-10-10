"""Message Phishing Classifier Training — M7.

Trains a lightweight scikit-learn TF-IDF + LogisticRegression model on the
synthetic message dataset and exports versioned model artifacts to
``ml/models/message_model_v1/``.

DISCLAIMER:
Uses a deterministic synthetic dataset for demonstration and testing.
Marked as NON-PRODUCTION.
"""

from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer

MODEL_VERSION = "message-v1"
FEATURE_SCHEMA_VERSION = "v1"
RANDOM_SEED = 42
CLASSIFICATION_THRESHOLD = 0.5


def load_dataset(csv_path: Path) -> tuple[list[str], list[int]]:
    """Load text messages and integer labels from CSV."""
    texts: list[str] = []
    labels: list[int] = []

    with open(csv_path, encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith("#") or row[0] == "label":
                continue
            label = int(row[0])
            subject = row[1] if len(row) > 1 else ""
            message = row[2] if len(row) > 2 else ""
            combined = f"{subject}\n{message}".strip()
            texts.append(combined)
            labels.append(label)

    return texts, labels


def train() -> dict[str, Any]:
    """Train pipeline, evaluate, and save versioned artifacts."""
    base_dir = Path(__file__).resolve().parent.parent
    dataset_path = base_dir / "datasets" / "synthetic_messages.csv"
    output_dir = base_dir / "models" / "message_model_v1"
    output_dir.mkdir(parents=True, exist_ok=True)

    texts, labels = load_dataset(dataset_path)

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=0.25,
        random_state=RANDOM_SEED,
        stratify=labels,
    )

    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    ngram_range=(1, 2),
                    max_features=500,
                    stop_words="english",
                    sublinear_tf=True,
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    C=1.0,
                    random_state=RANDOM_SEED,
                    max_iter=1000,
                ),
            ),
        ]
    )

    pipeline.fit(X_train, y_train)

    # Evaluation on test split
    y_pred_proba = pipeline.predict_proba(X_test)[:, 1]
    y_pred = (y_pred_proba >= CLASSIFICATION_THRESHOLD).astype(int)

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()

    # Save model.pkl first
    model_path = output_dir / "model.pkl"
    joblib.dump(pipeline, model_path)

    # Compute SHA-256 checksum for artifact integrity verification
    with open(model_path, "rb") as f:
        model_sha256 = hashlib.sha256(f.read()).hexdigest()

    # Extract vocabulary terms
    tfidf_step: TfidfVectorizer = pipeline.named_steps["tfidf"]
    vocab = list(tfidf_step.vocabulary_.keys())

    # Metadata
    metadata = {
        "model_version": MODEL_VERSION,
        "model_type": "TfidfVectorizer + LogisticRegression",
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "model_sha256": model_sha256,
        "classification_threshold": CLASSIFICATION_THRESHOLD,
        "random_seed": RANDOM_SEED,
        "dataset_path": "synthetic_messages.csv",
        "dataset_version": "synthetic-fixture-v1",
        "dataset_size": len(texts),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "training_note": (
            "NON-PRODUCTION: Synthetic fixture dataset for M7 message ML pipeline demonstration. "
            "Synthetic dataset — not production representative. "
            "Metrics reflect deterministic fixture data. Replace with real-world corpus for production."
        ),
        "test_accuracy": acc,
        "test_precision": prec,
        "test_recall": rec,
        "test_f1": f1,
        "test_confusion_matrix": cm,
        "vocabulary_size": len(vocab),
        "training_date": datetime.now(timezone.utc).isoformat(),
    }

    metadata_path = output_dir / "metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    # Feature schema
    feature_schema = {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "preprocessor": "TfidfVectorizer",
        "ngram_range": [1, 2],
        "max_features": 500,
        "vocabulary_sample": vocab[:50],
        "total_terms": len(vocab),
    }
    schema_path = output_dir / "feature_schema.json"
    with open(schema_path, "w", encoding="utf-8") as f:
        json.dump(feature_schema, f, indent=2)

    return metadata


if __name__ == "__main__":
    meta = train()
    print("Training complete:")
    print(f"  Model version: {meta['model_version']}")
    print(f"  Accuracy:      {meta['test_accuracy']:.4f}")
    print(f"  F1-Score:      {meta['test_f1']:.4f}")
    print(f"  Model SHA-256: {meta['model_sha256']}")
