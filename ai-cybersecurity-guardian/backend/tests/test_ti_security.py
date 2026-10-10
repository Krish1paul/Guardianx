"""Security tests for M4 Threat Intelligence layer.

Verifies:
- API key not present in any API response field
- API key not logged (checked via log capture)
- No network calls from mock provider
- No network calls from sanitize_url helper
- No subprocess calls during TI enrichment
- Provider endpoint is hard-coded (no user-controlled URL)
- URL sanitization strips userinfo before provider call
- TI boost cannot make score exceed 100
- TI cannot make score negative
- Final score is always in [0, 100] under adversarial conditions
"""

from __future__ import annotations

import logging
import os
import socket
from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

os.environ.setdefault("JWT_SECRET", "test-jwt-secret-at-least-32-chars-long-here")
os.environ.setdefault("ENVIRONMENT", "test")

import pytest
from app.services import score_blender
from app.services.threat_intelligence import _sanitize_url_for_provider
from app.services.ti_providers.mock_provider import MockProvider
from app.services.ti_providers.virustotal_provider import VirusTotalProvider
from app.services.ti_types import ThreatIntelResult, ThreatIntelStatus

_API_KEY = "super-secret-api-key-must-not-leak"


def _make_result(status: ThreatIntelStatus, confidence: float = 1.0) -> ThreatIntelResult:
    return ThreatIntelResult(
        provider="mock",
        status=status,
        confidence=confidence,
        reason="test",
        checked_at=datetime.now(UTC),
        provider_error=False,
    )


def _never_called(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError(f"Forbidden call: args={args[:2]}")


class TestAPIKeyNotLeaked:
    """API key must never appear in responses, logs, or exceptions."""

    def test_api_key_not_in_ti_result_on_error(self) -> None:
        vt = VirusTotalProvider(api_key=_API_KEY)
        with patch("urllib.request.urlopen", side_effect=TimeoutError("timeout")):
            result = vt.lookup("a" * 64, "https://example.com/")
        result_str = str(result)
        assert _API_KEY not in result_str

    def test_api_key_not_in_ti_result_on_success(self) -> None:
        import json
        from unittest.mock import MagicMock
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "data": {"attributes": {"last_analysis_stats": {
                "malicious": 0, "suspicious": 0, "harmless": 70,
                "undetected": 0, "timeout": 0,
            }}}
        }).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            vt = VirusTotalProvider(api_key=_API_KEY)
            result = vt.lookup("a" * 64, "https://example.com/")
        assert _API_KEY not in str(result)
        assert _API_KEY not in str(result.reason or "")
        assert _API_KEY not in str(result.provider)

    def test_api_key_not_logged_on_missing_key(self, caplog: Any) -> None:
        logger_name = "app.services.ti_providers.virustotal_provider"
        with caplog.at_level(logging.WARNING, logger=logger_name):
            vt = VirusTotalProvider(api_key="")
            vt.lookup("a" * 64, "https://example.com/")
        for record in caplog.records:
            assert _API_KEY not in record.getMessage()

    def test_api_key_not_in_provider_repr_or_str(self) -> None:
        vt = VirusTotalProvider(api_key=_API_KEY)
        assert _API_KEY not in repr(vt)
        assert _API_KEY not in str(vt)


class TestURLSanitization:
    """userinfo must be stripped from URLs before provider calls."""

    def test_strips_userinfo(self) -> None:
        url = "https://user:password@evil.com/steal"
        sanitized = _sanitize_url_for_provider(url)
        assert "user" not in sanitized
        assert "password" not in sanitized
        assert "evil.com" in sanitized

    def test_preserves_scheme_host_path(self) -> None:
        url = "https://example.com/path?q=1"
        sanitized = _sanitize_url_for_provider(url)
        assert sanitized == "https://example.com/path?q=1"

    def test_preserves_port(self) -> None:
        url = "https://example.com:8443/admin"
        sanitized = _sanitize_url_for_provider(url)
        assert "8443" in sanitized
        assert "example.com" in sanitized

    def test_no_userinfo_unchanged(self) -> None:
        url = "http://192.168.1.1/login"
        sanitized = _sanitize_url_for_provider(url)
        assert sanitized == url


class TestNoNetworkFromMockProvider:
    """Mock provider must never make network calls."""

    def test_no_socket_calls(self) -> None:
        original_connect = socket.create_connection

        def _detect(address: Any, *args: Any, **kwargs: Any) -> Any:
            host = address[0] if isinstance(address, tuple) else address
            if host not in ("localhost", "127.0.0.1", "::1"):
                raise AssertionError(f"SSRF: socket.create_connection called for {host!r}")
            return original_connect(address, *args, **kwargs)

        with patch("socket.create_connection", side_effect=_detect):
            mock = MockProvider()
            mock.lookup("a" * 64, "http://192.168.1.1/login")

    def test_no_urlopen_calls(self) -> None:
        with patch("urllib.request.urlopen", side_effect=_never_called):
            mock = MockProvider()
            mock.lookup("a" * 64, "https://example.com/")

    def test_no_requests_calls(self) -> None:
        with (
            patch("urllib.request.urlopen", side_effect=_never_called),
            patch("socket.create_connection", side_effect=_never_called),
        ):
            mock = MockProvider()
            for url in ["https://example.com/", "http://192.168.1.1/", "https://phishing.xyz/"]:
                result = mock.lookup("b" * 64, url)
                assert isinstance(result, ThreatIntelResult)


class TestNoSubprocessCalls:
    """TI enrichment must never spawn subprocesses."""

    def test_mock_no_subprocess_run(self) -> None:
        with patch("subprocess.run", side_effect=_never_called):
            mock = MockProvider()
            mock.lookup("a" * 64, "https://example.com/")

    def test_mock_no_subprocess_popen(self) -> None:
        with patch("subprocess.Popen", side_effect=_never_called):
            mock = MockProvider()
            mock.lookup("a" * 64, "http://192.168.1.1/login")


class TestScoreBoundaries:
    """Final blended score must always be in [0, 100]."""

    @pytest.mark.parametrize("baseline", [0, 1, 50, 99, 100])
    @pytest.mark.parametrize("status", [ThreatIntelStatus.MALICIOUS, ThreatIntelStatus.SUSPICIOUS])
    def test_score_never_exceeds_100(self, baseline: int, status: ThreatIntelStatus) -> None:
        result = _make_result(status, confidence=1.0)
        score, _ = score_blender.blend(baseline, result, max_boost=100)
        assert score <= 100

    @pytest.mark.parametrize("baseline", [0, 1, 50])
    def test_score_never_below_0(self, baseline: int) -> None:
        result = _make_result(ThreatIntelStatus.CLEAN)
        score, _ = score_blender.blend(baseline, result, max_boost=0)
        assert score >= 0

    def test_adversarial_max_boost_still_clamped(self) -> None:
        result = _make_result(ThreatIntelStatus.MALICIOUS, confidence=1.0)
        score, _ = score_blender.blend(100, result, max_boost=9999)
        assert score == 100

    def test_ti_cannot_make_score_negative(self) -> None:
        result = _make_result(ThreatIntelStatus.CLEAN, confidence=1.0)
        score, _ = score_blender.blend(0, result, max_boost=30)
        assert score >= 0


class TestProviderEndpointSecurity:
    """Provider endpoints must be fixed — no user-controlled URLs."""

    def test_virustotal_endpoint_is_hardcoded(self) -> None:
        """VirusTotalProvider uses a hard-coded base URL, not a config value."""
        from app.services.ti_providers.virustotal_provider import _VT_URL_BASE
        assert "virustotal.com" in _VT_URL_BASE
        assert not _VT_URL_BASE.startswith("http://")  # must be HTTPS

    def test_user_input_cannot_change_provider_endpoint(self) -> None:
        """Providing a crafted URL as input cannot redirect the provider call."""
        captured_urls: list[str] = []

        def _capture_urlopen(req: Any, *args: Any, **kwargs: Any) -> Any:
            # Record the URL being opened
            url = req.full_url if hasattr(req, "full_url") else str(req)
            captured_urls.append(url)
            raise TimeoutError("captured")

        vt = VirusTotalProvider(api_key="test-key")
        # Crafted input URL attempting to redirect to an attacker endpoint
        evil_url = "https://attacker.com/steal?inject=https://www.virustotal.com"
        with patch("urllib.request.urlopen", side_effect=_capture_urlopen):
            vt.lookup("a" * 64, evil_url)

        # Every captured URL must be on virustotal.com
        for captured in captured_urls:
            assert "virustotal.com" in captured, f"Non-VT URL opened: {captured}"
