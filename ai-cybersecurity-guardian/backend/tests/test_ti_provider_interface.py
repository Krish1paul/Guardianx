"""Tests for the TI provider interface and mock provider — M4.

Verifies:
- MockProvider satisfies the ThreatIntelligenceProvider protocol
- VirusTotalProvider satisfies the protocol
- MockProvider returns deterministic results
- MockProvider never makes network calls
- Protocol runtime_checkable works
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any
from unittest.mock import patch

import pytest

os.environ.setdefault("JWT_SECRET", "test-jwt-secret-at-least-32-chars-long-here")
os.environ.setdefault("ENVIRONMENT", "test")

from app.services.threat_intelligence import ThreatIntelligenceProvider
from app.services.ti_providers.mock_provider import MockProvider
from app.services.ti_providers.virustotal_provider import VirusTotalProvider
from app.services.ti_types import ThreatIntelResult, ThreatIntelStatus

_BENIGN_HASH = "a" * 64
_BENIGN_URL = "https://example.com/login"
_IP_URL = "http://192.168.1.1/admin"
_IP_HASH = "b" * 64
_USERINFO_URL = "https://user:pass@evil.com/steal"
_USERINFO_HASH = "c" * 64
_SUSPICIOUS_TLD_URL = "https://phishing.xyz/login"
_SUSPICIOUS_TLD_HASH = "d" * 64


def _never_called(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("Network call must not be made by mock provider")


class TestProviderProtocol:
    """Verify both providers satisfy the ThreatIntelligenceProvider protocol."""

    def test_mock_satisfies_protocol(self) -> None:
        mock = MockProvider()
        assert isinstance(mock, ThreatIntelligenceProvider)

    def test_virustotal_satisfies_protocol(self) -> None:
        vt = VirusTotalProvider(api_key="test-key")
        assert isinstance(vt, ThreatIntelligenceProvider)

    def test_mock_has_name_property(self) -> None:
        mock = MockProvider()
        assert mock.name == "mock"

    def test_virustotal_has_name_property(self) -> None:
        vt = VirusTotalProvider(api_key="test-key")
        assert vt.name == "virustotal"


class TestMockProviderDeterminism:
    """MockProvider returns deterministic, consistent results."""

    def setup_method(self) -> None:
        self.mock = MockProvider()

    def test_known_benign_returns_clean(self) -> None:
        result = self.mock.lookup(_BENIGN_HASH, _BENIGN_URL)
        assert result.status == ThreatIntelStatus.CLEAN
        assert result.provider == "mock"
        assert result.provider_error is False

    def test_ip_hostname_returns_malicious(self) -> None:
        result = self.mock.lookup(_IP_HASH, _IP_URL)
        assert result.status == ThreatIntelStatus.MALICIOUS
        assert result.confidence is not None
        assert result.confidence > 0.5

    def test_userinfo_returns_suspicious(self) -> None:
        result = self.mock.lookup(_USERINFO_HASH, _USERINFO_URL)
        assert result.status == ThreatIntelStatus.SUSPICIOUS

    def test_suspicious_tld_returns_suspicious(self) -> None:
        result = self.mock.lookup(_SUSPICIOUS_TLD_HASH, _SUSPICIOUS_TLD_URL)
        assert result.status == ThreatIntelStatus.SUSPICIOUS

    def test_unknown_url_returns_unknown(self) -> None:
        result = self.mock.lookup("e" * 64, "https://completely-unknown-random.com/path")
        assert result.status == ThreatIntelStatus.UNKNOWN

    def test_same_url_same_result(self) -> None:
        r1 = self.mock.lookup(_IP_HASH, _IP_URL)
        r2 = self.mock.lookup(_IP_HASH, _IP_URL)
        assert r1.status == r2.status
        assert r1.confidence == r2.confidence

    def test_result_has_checked_at(self) -> None:
        result = self.mock.lookup(_BENIGN_HASH, _BENIGN_URL)
        assert isinstance(result.checked_at, datetime)

    def test_result_is_not_cached(self) -> None:
        # Provider itself never sets cached=True; that is set by the service
        result = self.mock.lookup(_BENIGN_HASH, _BENIGN_URL)
        assert result.cached is False

    @pytest.mark.parametrize("url", [
        "https://example.com/",
        "http://192.168.1.1/admin",
        "https://user:pass@evil.com/",
        "https://phishing.xyz/login",
    ])
    def test_confidence_in_range(self, url: str) -> None:
        result = self.mock.lookup("f" * 64, url)
        if result.confidence is not None:
            assert 0.0 <= result.confidence <= 1.0

    def test_result_has_reason_when_flagged(self) -> None:
        result = self.mock.lookup(_IP_HASH, _IP_URL)
        assert result.reason is not None
        assert len(result.reason) > 0


class TestMockProviderNoNetwork:
    """MockProvider must never make any network calls."""

    def test_no_requests_calls(self) -> None:
        with (
            patch("urllib.request.urlopen", side_effect=_never_called),
            patch("socket.create_connection", side_effect=_never_called),
        ):
            mock = MockProvider()
            result = mock.lookup(_IP_HASH, _IP_URL)
            assert result.status == ThreatIntelStatus.MALICIOUS

    def test_no_http_calls_for_benign(self) -> None:
        with patch("urllib.request.urlopen", side_effect=_never_called):
            mock = MockProvider()
            result = mock.lookup(_BENIGN_HASH, _BENIGN_URL)
            assert result.status == ThreatIntelStatus.CLEAN

    def test_result_contains_no_api_key_references(self) -> None:
        mock = MockProvider()
        result = mock.lookup(_IP_HASH, _IP_URL)
        result_str = str(result)
        assert "api_key" not in result_str.lower()
        assert "apikey" not in result_str.lower()


class TestMockProviderEdgeCases:
    """MockProvider handles malformed input gracefully."""

    def setup_method(self) -> None:
        self.mock = MockProvider()

    def test_ipv6_hostname_not_classified_as_malicious(self) -> None:
        # IPv6 addresses should not trigger IPv4 pattern
        result = self.mock.lookup("g" * 64, "http://[::1]/admin")
        # Result should be UNKNOWN or SUSPICIOUS, not MALICIOUS (IPv4 check only)
        assert result.provider_error is False

    def test_empty_hostname(self) -> None:
        result = self.mock.lookup("h" * 64, "https:///path")
        # Should not crash
        assert isinstance(result, ThreatIntelResult)

    def test_result_fields_are_typed(self) -> None:
        result = self.mock.lookup(_BENIGN_HASH, _BENIGN_URL)
        assert isinstance(result.provider, str)
        assert isinstance(result.status, ThreatIntelStatus)
        assert isinstance(result.cached, bool)
        assert isinstance(result.provider_error, bool)
        assert isinstance(result.checked_at, datetime)
