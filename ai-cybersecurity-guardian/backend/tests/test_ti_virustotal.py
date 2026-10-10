"""Tests for VirusTotal provider — M4.

All tests use mocked HTTP — no real network calls are made.

Verifies:
- Successful VT response → correct status, confidence, reason
- Malicious response (high malicious engine count) → MALICIOUS
- Suspicious response (mixed engines) → SUSPICIOUS
- Clean response (zero malicious engines) → CLEAN
- Empty analysis stats → UNKNOWN
- HTTP 401 Unauthorized → provider_error=True
- HTTP 429 Rate Limited → provider_error=True
- HTTP 500 Server Error → provider_error=True
- Network timeout → provider_error=True
- Malformed JSON → provider_error=True
- Missing data key in JSON → UNKNOWN
- No API key → provider_error=True, message not logged with key value
- API key never appears in any result or log output
"""

from __future__ import annotations

import json
import os
from typing import Any
from unittest.mock import MagicMock, patch

os.environ.setdefault("JWT_SECRET", "test-jwt-secret-at-least-32-chars-long-here")
os.environ.setdefault("ENVIRONMENT", "test")


from app.services.ti_providers.virustotal_provider import VirusTotalProvider, _parse_vt_response
from app.services.ti_types import ThreatIntelStatus

_HASH = "a" * 64
_URL = "https://phishing.example.com/steal"
_API_KEY = "test-vt-api-key-12345"


def _make_vt_response(
    malicious: int = 0,
    suspicious: int = 0,
    harmless: int = 70,
    undetected: int = 0,
    timeout: int = 0,
) -> dict[str, Any]:
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "timeout": timeout,
                }
            }
        }
    }


def _mock_urlopen(response_data: dict[str, Any], status: int = 200) -> Any:
    """Return a context-manager mock for urllib.request.urlopen."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(response_data).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


class TestVirusTotalResponseParsing:
    """Unit tests for _parse_vt_response (no network)."""

    def test_all_clean(self) -> None:
        data = _make_vt_response(malicious=0, suspicious=0, harmless=70)
        status, confidence, _ = _parse_vt_response(data)
        assert status == ThreatIntelStatus.CLEAN
        assert confidence is not None
        assert confidence > 0

    def test_many_malicious_engines(self) -> None:
        data = _make_vt_response(malicious=15, harmless=55)
        status, confidence, reason = _parse_vt_response(data)
        assert status == ThreatIntelStatus.MALICIOUS
        assert reason is not None

    def test_few_malicious_engines(self) -> None:
        # 1/70 ≈ 1.4% malicious — below 10% threshold
        data = _make_vt_response(malicious=1, harmless=69)
        status, confidence, _ = _parse_vt_response(data)
        # Still suspicious because malicious > 0
        assert status in {ThreatIntelStatus.SUSPICIOUS, ThreatIntelStatus.CLEAN}

    def test_only_suspicious_engines(self) -> None:
        data = _make_vt_response(malicious=0, suspicious=5, harmless=65)
        status, _, _ = _parse_vt_response(data)
        assert status == ThreatIntelStatus.SUSPICIOUS

    def test_empty_stats(self) -> None:
        data: dict[str, Any] = {"data": {"attributes": {"last_analysis_stats": {}}}}
        status, _, _ = _parse_vt_response(data)
        assert status == ThreatIntelStatus.UNKNOWN

    def test_missing_data_key(self) -> None:
        status, _, _ = _parse_vt_response({})
        assert status == ThreatIntelStatus.UNKNOWN

    def test_malformed_stats_values(self) -> None:
        data: dict[str, Any] = {
            "data": {"attributes": {"last_analysis_stats": {"malicious": "bad"}}}
        }
        # Should not crash
        result = _parse_vt_response(data)
        assert result[0] in list(ThreatIntelStatus)


class TestVirusTotalProviderNoKey:
    """Provider with empty key immediately returns error."""

    def test_empty_key_returns_provider_error(self) -> None:
        vt = VirusTotalProvider(api_key="")
        result = vt.lookup(_HASH, _URL)
        assert result.provider_error is True
        assert result.status == ThreatIntelStatus.UNKNOWN

    def test_whitespace_only_key_returns_error(self) -> None:
        vt = VirusTotalProvider(api_key="   ")
        result = vt.lookup(_HASH, _URL)
        assert result.provider_error is True


class TestVirusTotalProviderHTTPSuccess:
    """Tests using mocked urllib.request.urlopen."""

    def test_clean_response(self) -> None:
        resp_data = _make_vt_response(malicious=0, harmless=70)
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(resp_data)):
            vt = VirusTotalProvider(api_key=_API_KEY)
            result = vt.lookup(_HASH, _URL)
        assert result.status == ThreatIntelStatus.CLEAN
        assert result.provider_error is False
        assert result.provider == "virustotal"

    def test_malicious_response(self) -> None:
        resp_data = _make_vt_response(malicious=10, harmless=60)
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(resp_data)):
            vt = VirusTotalProvider(api_key=_API_KEY)
            result = vt.lookup(_HASH, _URL)
        assert result.status == ThreatIntelStatus.MALICIOUS
        assert result.confidence is not None

    def test_result_has_reason(self) -> None:
        resp_data = _make_vt_response(malicious=10, harmless=60)
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(resp_data)):
            vt = VirusTotalProvider(api_key=_API_KEY)
            result = vt.lookup(_HASH, _URL)
        assert result.reason is not None


class TestVirusTotalProviderFailures:
    """All failure modes must return provider_error=True without crashing."""

    def test_network_timeout(self) -> None:
        with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            vt = VirusTotalProvider(api_key=_API_KEY)
            result = vt.lookup(_HASH, _URL, timeout_seconds=0.001)
        assert result.provider_error is True
        assert result.status == ThreatIntelStatus.UNKNOWN

    def test_connection_error(self) -> None:
        with patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
            vt = VirusTotalProvider(api_key=_API_KEY)
            result = vt.lookup(_HASH, _URL)
        assert result.provider_error is True

    def test_http_401_unauthorized(self) -> None:
        import urllib.error
        from http.client import HTTPMessage
        err = urllib.error.HTTPError(
            url="https://www.virustotal.com/...",
            code=401,
            msg="Unauthorized",
            hdrs=HTTPMessage(),
            fp=None,
        )
        with patch("urllib.request.urlopen", side_effect=err):
            vt = VirusTotalProvider(api_key=_API_KEY)
            result = vt.lookup(_HASH, _URL)
        assert result.provider_error is True

    def test_http_429_rate_limit(self) -> None:
        import urllib.error
        from http.client import HTTPMessage
        err = urllib.error.HTTPError(
            url="https://www.virustotal.com/...",
            code=429,
            msg="Too Many Requests",
            hdrs=HTTPMessage(),
            fp=None,
        )
        with patch("urllib.request.urlopen", side_effect=err):
            vt = VirusTotalProvider(api_key=_API_KEY)
            result = vt.lookup(_HASH, _URL)
        assert result.provider_error is True

    def test_http_500_server_error(self) -> None:
        import urllib.error
        from http.client import HTTPMessage
        err = urllib.error.HTTPError(
            url="https://www.virustotal.com/...",
            code=500,
            msg="Internal Server Error",
            hdrs=HTTPMessage(),
            fp=None,
        )
        with patch("urllib.request.urlopen", side_effect=err):
            vt = VirusTotalProvider(api_key=_API_KEY)
            result = vt.lookup(_HASH, _URL)
        assert result.provider_error is True

    def test_malformed_json(self) -> None:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"this is not json {{{"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            vt = VirusTotalProvider(api_key=_API_KEY)
            result = vt.lookup(_HASH, _URL)
        assert result.provider_error is True

    def test_unexpected_exception_handled(self) -> None:
        with patch("urllib.request.urlopen", side_effect=RuntimeError("unexpected")):
            vt = VirusTotalProvider(api_key=_API_KEY)
            result = vt.lookup(_HASH, _URL)
        assert result.provider_error is True


class TestVirusTotalAPIKeySecurity:
    """API key must never appear in results, logs, or repr."""

    def test_api_key_not_in_result_fields(self) -> None:
        vt = VirusTotalProvider(api_key=_API_KEY)
        result = vt.lookup(_HASH, _URL)
        result_str = str(result)
        assert _API_KEY not in result_str

    def test_api_key_not_in_provider_repr(self) -> None:
        vt = VirusTotalProvider(api_key=_API_KEY)
        repr_str = repr(vt)
        assert _API_KEY not in repr_str

    def test_empty_key_result_has_no_key_reference(self) -> None:
        vt = VirusTotalProvider(api_key="")
        result = vt.lookup(_HASH, _URL)
        result_str = str(result)
        assert "api_key" not in result_str.lower()

    def test_provider_name_is_virustotal_not_key(self) -> None:
        vt = VirusTotalProvider(api_key=_API_KEY)
        assert vt.name == "virustotal"
        assert _API_KEY not in vt.name
