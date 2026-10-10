"""Tests for the ML training pipeline.

Uses the synthetic fixture dataset. Tests confirm:
- Training pipeline runs without error
- Model artifact is created and loadable
- Metadata JSON has all required keys
- Feature schema matches FEATURE_NAMES
- Model is serializable/deserializable
- Metrics are in valid ranges
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

FIXTURE_DATASET = os.path.join(
    _PROJECT_ROOT, "ml", "datasets", "fixtures", "sample_urls.csv"
)
MODEL_DIR = os.path.join(_PROJECT_ROOT, "ml", "models", "url_model_v1")

# Skip all tests in this module if fixture dataset is absent
pytestmark = pytest.mark.skipif(
    not os.path.exists(FIXTURE_DATASET),
    reason="Fixture dataset not available",
)


class TestTrainingPipelineRuns:
    """Verify training completes and creates the expected artifacts."""

    def test_model_pkl_exists_after_training(self) -> None:
        """model.pkl must exist (training script must have been run)."""
        model_path = os.path.join(MODEL_DIR, "model.pkl")
        assert os.path.isfile(model_path), f"model.pkl not found at {model_path}"
        assert os.path.getsize(model_path) > 0

    def test_metadata_json_exists(self) -> None:
        meta_path = os.path.join(MODEL_DIR, "metadata.json")
        assert os.path.isfile(meta_path)

    def test_feature_schema_json_exists(self) -> None:
        schema_path = os.path.join(MODEL_DIR, "feature_schema.json")
        assert os.path.isfile(schema_path)

    def test_metadata_has_required_keys(self) -> None:
        meta_path = os.path.join(MODEL_DIR, "metadata.json")
        with open(meta_path) as f:
            meta = json.load(f)
        required_keys = {
            "model_version",
            "model_type",
            "feature_schema_version",
            "feature_count",
            "feature_names",
            "classification_threshold",
            "random_seed",
            "dataset_size",
            "train_size",
            "val_size",
            "test_size",
            "training_note",
            "training_date",
        }
        missing = required_keys - meta.keys()
        assert not missing, f"metadata.json missing keys: {missing}"

    def test_metadata_model_version_is_ml_v1(self) -> None:
        meta_path = os.path.join(MODEL_DIR, "metadata.json")
        with open(meta_path) as f:
            meta = json.load(f)
        assert meta["model_version"] == "ml-v1"

    def test_metadata_threshold_in_valid_range(self) -> None:
        meta_path = os.path.join(MODEL_DIR, "metadata.json")
        with open(meta_path) as f:
            meta = json.load(f)
        threshold = meta["classification_threshold"]
        assert 0.0 <= threshold <= 1.0

    def test_metadata_sizes_are_positive(self) -> None:
        meta_path = os.path.join(MODEL_DIR, "metadata.json")
        with open(meta_path) as f:
            meta = json.load(f)
        assert meta["train_size"] > 0
        assert meta["val_size"] > 0
        assert meta["test_size"] > 0
        assert meta["dataset_size"] == meta["train_size"] + meta["val_size"] + meta["test_size"]

    def test_feature_schema_matches_feature_names(self) -> None:
        from ml.features.url_feature_vector import FEATURE_NAMES, FEATURE_SCHEMA_VERSION

        schema_path = os.path.join(MODEL_DIR, "feature_schema.json")
        with open(schema_path) as f:
            schema = json.load(f)
        assert schema["feature_schema_version"] == FEATURE_SCHEMA_VERSION
        assert schema["feature_names"] == FEATURE_NAMES
        assert schema["feature_count"] == len(FEATURE_NAMES)

    def test_model_is_loadable(self) -> None:
        import joblib

        model_path = os.path.join(MODEL_DIR, "model.pkl")
        model = joblib.load(model_path)
        assert model is not None

    def test_model_has_predict_proba(self) -> None:
        import joblib

        model_path = os.path.join(MODEL_DIR, "model.pkl")
        model = joblib.load(model_path)
        assert hasattr(model, "predict_proba")

    def test_model_produces_probability_on_sample(self) -> None:
        import joblib
        import numpy as np
        from ml.features import url_features
        from ml.features.url_feature_vector import features_to_vector

        model_path = os.path.join(MODEL_DIR, "model.pkl")
        model = joblib.load(model_path)
        f = url_features.extract("https://example.com/")
        vector = features_to_vector(f)
        x = np.array([vector])  # noqa: N806 — ML convention
        proba = model.predict_proba(x)
        assert proba.shape == (1, 2)
        assert 0.0 <= float(proba[0, 1]) <= 1.0
        # Probabilities must sum to ~1
        assert abs(float(proba[0, 0]) + float(proba[0, 1]) - 1.0) < 1e-6

    def test_training_note_mentions_synthetic(self) -> None:
        meta_path = os.path.join(MODEL_DIR, "metadata.json")
        with open(meta_path) as f:
            meta = json.load(f)
        note: str = meta.get("training_note", "")
        assert "synthetic" in note.lower() or "fixture" in note.lower(), (
            "Training on synthetic data must be declared in training_note"
        )


class TestTrainFunctionDirectly:
    """Call train() in a temporary output dir to test the pipeline end-to-end."""

    def test_train_creates_artifacts_in_temp_dir(self, tmp_path: object) -> None:
        """Run training into a temp directory without touching the real model dir."""
        import ml.training.train_url_model as train_module

        original_output_dir = train_module.MODEL_OUTPUT_DIR
        train_module.MODEL_OUTPUT_DIR = str(tmp_path)

        try:
            train_module.train(
                dataset_path=FIXTURE_DATASET,
                dataset_version="test-fixture-v1",
            )
            assert os.path.isfile(os.path.join(str(tmp_path), "model.pkl"))
            assert os.path.isfile(os.path.join(str(tmp_path), "metadata.json"))
            assert os.path.isfile(os.path.join(str(tmp_path), "feature_schema.json"))
        finally:
            train_module.MODEL_OUTPUT_DIR = original_output_dir
