"""Security tests for M3 ML inference — extends M2 SSRF guarantees.

Verifies:
- No HTTP/HTTPS/socket/DNS requests during ML inference
- No subprocess calls
- Model path is fixed — user-controlled paths are rejected
- Corrupt model file → fallback, no crash
- Arbitrary model path outside project root is rejected
"""

from __future__ import annotations

import json
import os
import socket
import sys
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ml.features import url_features  # noqa: E402

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# ---------------------------------------------------------------------------
# Test URLs covering adversarial patterns
# ---------------------------------------------------------------------------

_TEST_URLS = [
    "https://example.com/login",
    "http://192.168.1.1/admin",
    "https://accounts.google.com/signin",
    "http://user:password@attacker.com/steal-creds",
    "https://xn--pypal-4ve.com/verify",
    "https://a.b.c.d.evil.xyz/login?credential=reset",
]


def _never_called(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError(
        f"This function must never be called during URL ML inference. args={args[:2]}"
    )


class TestMLSSRFSafety:
    """Verify ML inference makes no network calls."""

    @pytest.mark.parametrize("url", _TEST_URLS)
    def test_no_requests_calls_during_ml_inference(self, url: str) -> None:
        """requests.get/post/head must never be called during ML inference."""
        with (
            patch("requests.get", side_effect=_never_called),
            patch("requests.post", side_effect=_never_called),
            patch("requests.head", side_effect=_never_called),
            patch("requests.request", side_effect=_never_called),
        ):
            import ml.inference.url_inference as mod
            mod._state = None
            from ml.inference.url_inference import URLInferenceEngine
            engine = URLInferenceEngine()
            f = url_features.extract(url)
            result = engine.run(f)
            assert result is not None

    @pytest.mark.parametrize("url", _TEST_URLS)
    def test_no_httpx_calls_during_ml_inference(self, url: str) -> None:
        mock_httpx = MagicMock()
        mock_httpx.get = _never_called
        mock_httpx.post = _never_called
        mock_httpx.Client = _never_called
        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            from ml.inference.url_inference import URLInferenceEngine
            engine = URLInferenceEngine()
            f = url_features.extract(url)
            result = engine.run(f)
            assert result is not None

    @pytest.mark.parametrize("url", _TEST_URLS)
    def test_no_urllib_urlopen_during_ml_inference(self, url: str) -> None:
        with patch("urllib.request.urlopen", side_effect=_never_called):
            from ml.inference.url_inference import URLInferenceEngine
            engine = URLInferenceEngine()
            f = url_features.extract(url)
            result = engine.run(f)
            assert result is not None

    @pytest.mark.parametrize("url", _TEST_URLS)
    def test_no_socket_connect_during_ml_inference(self, url: str) -> None:
        """socket.create_connection must not be called for non-loopback hosts."""
        original_create_connection = socket.create_connection

        def _no_create_connection(address: Any, *args: Any, **kwargs: Any) -> Any:
            host = address[0] if isinstance(address, tuple) else address
            if host in ("localhost", "127.0.0.1", "::1", ""):
                return original_create_connection(address, *args, **kwargs)
            raise AssertionError(
                f"SSRF VIOLATION: socket.create_connection called for host {host!r}"
            )

        with patch("socket.create_connection", side_effect=_no_create_connection):
            from ml.inference.url_inference import URLInferenceEngine
            engine = URLInferenceEngine()
            f = url_features.extract(url)
            result = engine.run(f)
            assert result is not None


class TestMLSubprocessSafety:
    """ML inference must not spawn subprocesses."""

    @pytest.mark.parametrize("url", _TEST_URLS)
    def test_no_subprocess_run(self, url: str) -> None:
        with patch("subprocess.run", side_effect=_never_called):
            from ml.inference.url_inference import URLInferenceEngine
            engine = URLInferenceEngine()
            f = url_features.extract(url)
            engine.run(f)

    @pytest.mark.parametrize("url", _TEST_URLS)
    def test_no_subprocess_popen(self, url: str) -> None:
        with patch("subprocess.Popen", side_effect=_never_called):
            from ml.inference.url_inference import URLInferenceEngine
            engine = URLInferenceEngine()
            f = url_features.extract(url)
            engine.run(f)


class TestMLModelPathSecurity:
    """Model loading is restricted to the trusted project directory."""

    def test_model_dir_is_inside_project_root(self) -> None:
        import ml.inference.url_inference as mod
        real_model_dir = os.path.realpath(mod._MODEL_DIR)
        real_project_root = os.path.realpath(_PROJECT_ROOT)
        assert real_model_dir.startswith(real_project_root), (
            f"Model dir {real_model_dir!r} is outside project root {real_project_root!r}"
        )

    def test_path_outside_project_triggers_fallback(self) -> None:
        """A model directory outside the project root must be rejected."""
        import ml.inference.url_inference as mod
        original_state = mod._state
        original_dir = mod._MODEL_DIR
        original_pkl = mod._MODEL_PKL
        original_meta = mod._METADATA_JSON
        original_schema = mod._SCHEMA_JSON

        mod._state = None
        mod._MODEL_DIR = "/tmp/evil_model"
        mod._MODEL_PKL = "/tmp/evil_model/model.pkl"
        mod._METADATA_JSON = "/tmp/evil_model/metadata.json"
        mod._SCHEMA_JSON = "/tmp/evil_model/feature_schema.json"

        try:
            from ml.inference.url_inference import URLInferenceEngine
            engine = URLInferenceEngine()
            f = url_features.extract("https://example.com/")
            result = engine.run(f)
            # Must fall back — never use ml-v1 from an untrusted path
            assert result.analyzer_version == "rule-v1"
        finally:
            mod._state = original_state
            mod._MODEL_DIR = original_dir
            mod._MODEL_PKL = original_pkl
            mod._METADATA_JSON = original_meta
            mod._SCHEMA_JSON = original_schema

    def test_corrupt_model_file_triggers_fallback(self, tmp_path: object) -> None:
        """Corrupt model.pkl must not crash — fallback to rule-v1."""
        import ml.inference.url_inference as mod
        from ml.features.url_feature_vector import FEATURE_NAMES, FEATURE_SCHEMA_VERSION

        schema = {
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "feature_count": len(FEATURE_NAMES),
            "feature_names": FEATURE_NAMES,
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
            f.write("corrupt data")

        original_state = mod._state
        original_dir = mod._MODEL_DIR
        original_pkl = mod._MODEL_PKL
        original_meta = mod._METADATA_JSON
        original_schema = mod._SCHEMA_JSON

        mod._state = None
        mod._MODEL_DIR = str(tmp_path)
        mod._MODEL_PKL = pkl_path
        mod._METADATA_JSON = meta_path
        mod._SCHEMA_JSON = schema_path

        try:
            with patch("os.path.realpath", return_value=_PROJECT_ROOT):
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


class TestMLPureStringAnalysis:
    """Verify ML inference is pure string analysis — no I/O side effects."""

    def test_feature_extraction_does_not_open_sockets(self) -> None:
        original_connect = socket.create_connection

        def _detect_connection(address: Any, *args: Any, **kwargs: Any) -> Any:
            host = address[0] if isinstance(address, tuple) else address
            if host not in ("localhost", "127.0.0.1", "::1", ""):
                raise AssertionError(f"Network call detected for host {host!r}")
            return original_connect(address, *args, **kwargs)

        with patch("socket.create_connection", side_effect=_detect_connection):
            f = url_features.extract("http://192.168.99.99/login")
            from ml.features.url_feature_vector import features_to_vector
            vector = features_to_vector(f)
            assert len(vector) > 0

    def test_inference_engine_is_stateless_across_calls(self) -> None:
        """Same URLInferenceEngine instance produces identical results."""
        from ml.inference.url_inference import URLInferenceEngine
        engine = URLInferenceEngine()
        f = url_features.extract("http://192.168.1.1/login")
        results = [engine.run(f) for _ in range(3)]
        assert all(r.score == results[0].score for r in results)
        assert all(r.analyzer_version == results[0].analyzer_version for r in results)
