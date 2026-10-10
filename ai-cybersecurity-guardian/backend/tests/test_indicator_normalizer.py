"""Tests for IndicatorNormalizer — M8.

Verifies deterministic indicator normalization, eTLD+1 domain extraction,
hash normalization, and sender parsing without external network lookups.
"""

from __future__ import annotations

from app.services.intelligence.indicator_normalizer import (
    IndicatorNormalizer,
    IndicatorType,
)


class TestIndicatorNormalizer:
    """Test suite for analytical indicator normalization."""

    def test_extract_domain_parts_standard_tld(self) -> None:
        host, reg, sub = IndicatorNormalizer.extract_domain_parts("login.secure.paypal.com")
        assert host == "login.secure.paypal.com"
        assert reg == "paypal.com"
        assert sub == "login.secure"

    def test_extract_domain_parts_two_part_tld(self) -> None:
        host, reg, sub = IndicatorNormalizer.extract_domain_parts("portal.banking.co.uk")
        assert host == "portal.banking.co.uk"
        assert reg == "banking.co.uk"
        assert sub == "portal"

    def test_extract_domain_parts_bare_domain(self) -> None:
        host, reg, sub = IndicatorNormalizer.extract_domain_parts("github.com")
        assert host == "github.com"
        assert reg == "github.com"
        assert sub is None

    def test_extract_domain_parts_ipv4(self) -> None:
        host, reg, sub = IndicatorNormalizer.extract_domain_parts("192.168.1.100")
        assert host == "192.168.1.100"
        assert reg is None
        assert sub is None

    def test_extract_url_indicators(self) -> None:
        indicators = IndicatorNormalizer.extract_url_indicators(
            "https://paypa1-verify.ru/login?token=abc"
        )
        types = {i.type for i in indicators}
        assert IndicatorType.URL_HASH in types
        assert IndicatorType.HOSTNAME in types

        host_ind = next(i for i in indicators if i.type == IndicatorType.HOSTNAME)
        assert host_ind.value == "paypa1-verify.ru"

    def test_extract_url_indicators_with_subdomain(self) -> None:
        indicators = IndicatorNormalizer.extract_url_indicators(
            "https://auth.phish-domain.com/secure"
        )
        values = {i.value for i in indicators}
        assert "auth.phish-domain.com" in values
        assert "phish-domain.com" in values

    def test_normalize_hash(self) -> None:
        valid_sha = "A" * 64
        assert IndicatorNormalizer.normalize_hash(valid_sha) == "a" * 64

        invalid_sha = "xyz123"
        assert IndicatorNormalizer.normalize_hash(invalid_sha) is None

        short_sha = "a" * 63
        assert IndicatorNormalizer.normalize_hash(short_sha) is None

    def test_extract_sender_indicators_with_display_name(self) -> None:
        sender = "Security Team <alerts@paypal-security-update.xyz>"
        indicators = IndicatorNormalizer.extract_sender_indicators(sender)
        types = {i.type for i in indicators}
        assert IndicatorType.SENDER_EMAIL in types
        assert IndicatorType.SENDER_DOMAIN in types

        email_ind = next(i for i in indicators if i.type == IndicatorType.SENDER_EMAIL)
        assert email_ind.value == "alerts@paypal-security-update.xyz"

        domain_ind = next(i for i in indicators if i.type == IndicatorType.SENDER_DOMAIN)
        assert domain_ind.value == "paypal-security-update.xyz"

    def test_extract_sender_indicators_empty_or_none(self) -> None:
        assert IndicatorNormalizer.extract_sender_indicators(None) == []
        assert IndicatorNormalizer.extract_sender_indicators("   ") == []
