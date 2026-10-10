"""SSRF safety tests — M2.

Verifies that the URL analyzer makes NO network requests to the submitted URL.

Test strategy:
- Monkeypatch ``requests``, ``httpx``, and ``urllib.request`` to raise
  an exception if called.  If the analyzer ever calls them, the test fails.
- Run the full analysis pipeline against URLs that would be interesting
  targets (IP addresses, domains, redirect targets).

Security guarantee tested:
    The static URL analyzer is a pure string parser.  It must never
    initiate a network connection to the analyzed URL.
"""

from __future__ import annotations

import os
import socket
import sys
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app.core.url_utils import normalize_url, validate_url
from ml.features import url_features
from ml.features.url_risk_engine import URLRiskEngine
from ml.inference.url_inference import URLInferenceEngine


def _never_called(*args: Any, **kwargs: Any) -> None:
    """Sentinel that fails the test if called."""
    raise AssertionError(
        "SSRF VIOLATION: Network request was attempted during URL analysis. "
        f"Called with args={args!r} kwargs={kwargs!r}"
    )


_TEST_URLS = [
    "https://example.com/login",
    "http://192.168.1.1/admin",
    "https://accounts.google.com/signin",
    "http://user:password@attacker.com/steal-creds",
    "https://xn--pypal-4ve.com/verify",
    "https://a.b.c.d.evil.xyz/login?credential=reset",
    "https://192.168.0.1:8080/",
]


class TestSSRFSafety:
    """Verify that NO network I/O occurs during URL analysis."""

    @pytest.mark.parametrize("url", _TEST_URLS)
    def test_no_requests_get(self, url: str) -> None:
        """requests.get must never be called."""
        with (
            patch("requests.get", side_effect=_never_called),
            patch("requests.post", side_effect=_never_called),
            patch("requests.head", side_effect=_never_called),
            patch("requests.request", side_effect=_never_called),
        ):
            validate_url(url)
            normalized = normalize_url(url)
            features = url_features.extract(normalized)
            engine = URLInferenceEngine()
            engine.run(features)

    @pytest.mark.parametrize("url", _TEST_URLS)
    def test_no_httpx_calls(self, url: str) -> None:
        """httpx.get / httpx.Client must never be called."""
        mock_httpx = MagicMock()
        mock_httpx.get = _never_called
        mock_httpx.post = _never_called
        mock_httpx.Client = _never_called

        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            validate_url(url)
            normalized = normalize_url(url)
            features = url_features.extract(normalized)
            engine = URLInferenceEngine()
            engine.run(features)

    @pytest.mark.parametrize("url", _TEST_URLS)
    def test_no_urllib_urlopen(self, url: str) -> None:
        """urllib.request.urlopen must never be called."""
        with patch("urllib.request.urlopen", side_effect=_never_called):
            validate_url(url)
            normalized = normalize_url(url)
            features = url_features.extract(normalized)
            engine = URLInferenceEngine()
            engine.run(features)

    @pytest.mark.parametrize("url", _TEST_URLS)
    def test_no_socket_connect(self, url: str) -> None:
        """socket.create_connection must never be called for analyzed URLs.

        We patch at a high level; DNS resolution or TCP connections would
        go through socket.create_connection or socket.getaddrinfo.
        """
        original_create_connection = socket.create_connection

        def _no_create_connection(address: Any, *args: Any, **kwargs: Any) -> Any:
            host = address[0] if isinstance(address, tuple) else address
            # Allow loopback connections (test infrastructure)
            if host in ("localhost", "127.0.0.1", "::1", ""):
                return original_create_connection(address, *args, **kwargs)
            raise AssertionError(
                f"SSRF VIOLATION: socket.create_connection called for host {host!r}"
            )

        with patch("socket.create_connection", side_effect=_no_create_connection):
            validate_url(url)
            normalized = normalize_url(url)
            features = url_features.extract(normalized)
            engine = URLInferenceEngine()
            engine.run(features)


class TestPureStringAnalysis:
    """Verify analyzer is a pure string pipeline with no side effects."""

    def test_feature_extraction_is_pure(self) -> None:
        """Running extract() twice on same URL produces identical result."""
        url = "https://example.com/login?verify=1"
        f1 = url_features.extract(url)
        f2 = url_features.extract(url)
        assert f1 == f2

    def test_risk_engine_is_stateless(self) -> None:
        """Risk engine produces identical results across multiple calls."""
        engine = URLRiskEngine()
        url = "http://user:pass@192.168.1.1/login"
        features = url_features.extract(url)
        results = [engine.score(features) for _ in range(5)]
        scores = {r.score for r in results}
        assert len(scores) == 1, "Risk engine is not stateless — scores varied"

    def test_inference_engine_stateless(self) -> None:
        """Inference engine produces identical results across multiple calls."""
        engine = URLInferenceEngine()
        url = "https://xn--pypal-4ve.com/verify"
        features = url_features.extract(url)
        results = [engine.run(features) for _ in range(5)]
        scores = {r.score for r in results}
        assert len(scores) == 1
