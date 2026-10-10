"""Unit tests for Message ML training, inference, and artifact integrity — M7."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ml.features.message_features import extract_message_features
from ml.inference.message_inference import MessageInferenceEngine

MODEL_DIR = Path(__file__).resolve().parent.parent.parent / "ml" / "models" / "message_model_v1"


class TestMessageMLArtifacts:
    def test_artifacts_exist(self) -> None:
        assert (MODEL_DIR / "model.pkl").exists()
        assert (MODEL_DIR / "metadata.json").exists()
        assert (MODEL_DIR / "feature_schema.json").exists()

    def test_metadata_disclaimer_and_metrics(self) -> None:
        with open(MODEL_DIR / "metadata.json", encoding="utf-8") as f:
            meta = json.load(f)

        assert meta["model_version"] == "message-v1"
        assert "NON-PRODUCTION" in meta["training_note"]
        assert "Synthetic dataset — not production representative" in meta["training_note"]
        assert meta["model_sha256"] is not None
        assert len(meta["model_sha256"]) == 64
        assert "test_accuracy" in meta
        assert "test_f1" in meta
        assert "test_confusion_matrix" in meta

    def test_inference_engine_ready(self) -> None:
        engine = MessageInferenceEngine()
        assert engine.is_ready is True

        res = engine.predict("Urgent: your credentials must be verified now")
        assert not res.used_fallback
        assert 0.0 <= res.phishing_probability <= 1.0
        assert 0.5 <= res.confidence <= 1.0
        assert len(res.top_contributing_terms) > 0

    def test_integrity_tampering_fallback(self) -> None:
        """Verify that a corrupted model.pkl is detected via SHA-256 and falls back gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            # Copy metadata
            with open(MODEL_DIR / "metadata.json", encoding="utf-8") as f:
                meta = json.load(f)
            with open(tmppath / "metadata.json", "w", encoding="utf-8") as f:
                json.dump(meta, f)

            # Write corrupted model file with different SHA-256
            with open(tmppath / "model.pkl", "wb") as f:
                f.write(b"tampered-malformed-model-bytes")

            temp_engine = MessageInferenceEngine(model_dir=tmppath)
            assert temp_engine.is_ready is False

            # Prediction must still work via heuristic fallback without crashing
            features = extract_message_features("Urgent action required! Verify your password.")
            res = temp_engine.predict(
                "Urgent action required! Verify your password.", features=features
            )
            assert res.used_fallback is True
            assert res.phishing_probability >= 0.50

    def test_missing_artifact_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = MessageInferenceEngine(model_dir=Path(tmpdir))
            assert engine.is_ready is False

            features = extract_message_features("Hello meeting today")
            res = engine.predict("Hello meeting today", features=features)
            assert res.used_fallback is True
            assert res.phishing_probability <= 0.30
