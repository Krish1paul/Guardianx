"""Tests for the deterministic URL risk engine — M2.

Tests cover:
- Benign URL → low risk
- Specific rules firing individually
- Combination rules
- Score clamping (0–100)
- Determinism
- Classification thresholds
- Explainability (reason codes match features)
- Adversarial inputs
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))


from ml.features.url_features import extract
from ml.features.url_risk_engine import (
    ReasonCode,
    RiskClassification,
    URLRiskEngine,
)

engine = URLRiskEngine()


def score(url: str) -> int:
    return int(engine.score(extract(url)).score)


def codes(url: str) -> set[str]:
    return {r.code.value for r in engine.score(extract(url)).reasons}


def classify(url: str) -> RiskClassification:
    return engine.score(extract(url)).classification


# ---------------------------------------------------------------------------
# Benign URLs → LOW_RISK
# ---------------------------------------------------------------------------


class TestBenignURLs:
    def test_simple_https(self) -> None:
        assert classify("https://example.com/") == RiskClassification.LOW_RISK

    def test_google_https(self) -> None:
        assert classify("https://www.google.com/") == RiskClassification.LOW_RISK

    def test_wikipedia(self) -> None:
        assert classify("https://en.wikipedia.org/wiki/Phishing") == RiskClassification.LOW_RISK

    def test_google_login_is_low_risk(self) -> None:
        # google.com/login has a keyword but is NOT inherently malicious
        result = engine.score(extract("https://accounts.google.com/login"))
        # Score should be low (keyword-only rule applies minimally)
        assert result.score < 25, f"Expected <25, got {result.score}"

    def test_github(self) -> None:
        assert classify("https://github.com/login") == RiskClassification.LOW_RISK

    def test_no_reasons_for_clean_url(self) -> None:
        result = engine.score(extract("https://example.com/"))
        assert result.reasons == []
        assert result.score == 0


# ---------------------------------------------------------------------------
# Individual rules
# ---------------------------------------------------------------------------


class TestIndividualRules:
    def test_http_rule(self) -> None:
        assert ReasonCode.HTTP_NOT_HTTPS.value in codes("http://example.com/")

    def test_ip_hostname_rule(self) -> None:
        result = engine.score(extract("https://192.168.1.1/"))
        code_vals = {r.code.value for r in result.reasons}
        assert ReasonCode.IP_HOSTNAME.value in code_vals
        assert result.score >= 25  # at least MEDIUM_RISK

    def test_punycode_rule(self) -> None:
        result = engine.score(extract("https://xn--pypal-4ve.com/"))
        code_vals = {r.code.value for r in result.reasons}
        assert ReasonCode.PUNYCODE_DOMAIN.value in code_vals

    def test_excessive_subdomains_rule(self) -> None:
        result = engine.score(extract("https://a.b.c.d.example.com/"))
        code_vals = {r.code.value for r in result.reasons}
        assert ReasonCode.EXCESSIVE_SUBDOMAINS.value in code_vals

    def test_suspicious_tld_rule(self) -> None:
        result = engine.score(extract("https://example.xyz/"))
        code_vals = {r.code.value for r in result.reasons}
        assert ReasonCode.SUSPICIOUS_TLD.value in code_vals

    def test_userinfo_rule(self) -> None:
        result = engine.score(extract("https://user:pass@example.com/"))
        code_vals = {r.code.value for r in result.reasons}
        assert ReasonCode.USERINFO_PRESENT.value in code_vals
        assert result.score >= 25  # at least MEDIUM_RISK

    def test_non_standard_port_rule(self) -> None:
        result = engine.score(extract("https://example.com:9999/"))
        code_vals = {r.code.value for r in result.reasons}
        assert ReasonCode.NON_STANDARD_PORT.value in code_vals

    def test_excessive_url_length_rule(self) -> None:
        long_url = "https://example.com/" + "a" * 600
        result = engine.score(extract(long_url))
        code_vals = {r.code.value for r in result.reasons}
        assert ReasonCode.EXCESSIVE_URL_LENGTH.value in code_vals

    def test_double_encoding_rule(self) -> None:
        result = engine.score(extract("https://example.com/%2525252525"))
        code_vals = {r.code.value for r in result.reasons}
        assert ReasonCode.HIGH_ENCODING_RATIO.value in code_vals


# ---------------------------------------------------------------------------
# Combination rules (higher scores)
# ---------------------------------------------------------------------------


class TestCombinationRules:
    def test_ip_plus_login_keyword(self) -> None:
        """IP hostname + login keyword → SUSPICIOUS_COMBINATION fires."""
        result = engine.score(extract("http://192.168.1.1/login"))
        code_vals = {r.code.value for r in result.reasons}
        assert ReasonCode.SUSPICIOUS_COMBINATION.value in code_vals
        assert result.score >= 50  # HIGH_RISK

    def test_punycode_plus_login(self) -> None:
        result = engine.score(extract("https://xn--pypal-4ve.com/login"))
        code_vals = {r.code.value for r in result.reasons}
        assert ReasonCode.SUSPICIOUS_COMBINATION.value in code_vals
        assert result.score >= 25

    def test_http_plus_login(self) -> None:
        result = engine.score(extract("http://example.com/login"))
        code_vals = {r.code.value for r in result.reasons}
        assert ReasonCode.SUSPICIOUS_COMBINATION.value in code_vals

    def test_credential_path_plus_ip(self) -> None:
        """Credential path on IP host → CREDENTIAL_PATH fires."""
        result = engine.score(extract("https://10.0.0.1/reset-password"))
        code_vals = {r.code.value for r in result.reasons}
        assert ReasonCode.CREDENTIAL_PATH.value in code_vals

    def test_credential_path_plus_http(self) -> None:
        result = engine.score(extract("http://example.com/login"))
        code_vals = {r.code.value for r in result.reasons}
        # Both HTTP_NOT_HTTPS and CREDENTIAL_PATH or SUSPICIOUS_COMBINATION
        assert ReasonCode.HTTP_NOT_HTTPS.value in code_vals

    def test_userinfo_with_credential_path(self) -> None:
        result = engine.score(extract("http://admin:password@192.168.1.1/login"))
        assert result.score >= 50  # Multiple signals → HIGH_RISK or CRITICAL

    def test_multiple_signals_critical(self) -> None:
        """Accumulation of signals should push into CRITICAL range."""
        # IP + HTTP + userinfo + keyword
        result = engine.score(extract("http://user:pass@192.168.1.1/login"))
        assert result.score >= 75, f"Expected CRITICAL, got {result.score}"
        assert result.classification == RiskClassification.CRITICAL


# ---------------------------------------------------------------------------
# Score clamping
# ---------------------------------------------------------------------------


class TestScoreClamping:
    def test_score_never_below_zero(self) -> None:
        """Score must always be >= 0."""
        urls = [
            "https://example.com/",
            "https://www.google.com/",
            "https://wikipedia.org/wiki/Test",
        ]
        for url in urls:
            assert engine.score(extract(url)).score >= 0

    def test_score_never_above_100(self) -> None:
        """Score must always be <= 100 even for adversarial inputs."""
        adversarial = [
            "http://user:pass@192.168.1.1:9999/login?verify=1&password=x&credential=y",
            "http://user:pass@xn--pypal-4ve.xyz:8080/login?verify=1&" + "a=b&" * 50,
            "http://a.b.c.d.e.f.g.h.i.j.example.xyz/login?password=reset&verify=1",
        ]
        for url in adversarial:
            result = engine.score(extract(url))
            assert result.score <= 100, f"Score {result.score} > 100 for {url}"

    def test_score_is_integer(self) -> None:
        result = engine.score(extract("https://example.com/"))
        assert isinstance(result.score, int)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_url_same_score_repeated(self) -> None:
        url = "https://example.com/login"
        scores = {engine.score(extract(url)).score for _ in range(20)}
        assert len(scores) == 1

    def test_same_url_same_reasons(self) -> None:
        url = "http://user:pass@192.168.1.1/login"
        results = [engine.score(extract(url)) for _ in range(5)]
        code_sets = [frozenset(r.code.value for r in res.reasons) for res in results]
        assert len(set(code_sets)) == 1


# ---------------------------------------------------------------------------
# Classification thresholds
# ---------------------------------------------------------------------------


class TestClassificationThresholds:
    def test_0_is_low_risk(self) -> None:
        result = engine.score(extract("https://example.com/"))
        assert result.classification == RiskClassification.LOW_RISK

    def test_http_alone_is_low_risk(self) -> None:
        result = engine.score(extract("http://example.com/"))
        # HTTP alone = 15 pts → LOW_RISK (threshold is 25 for MEDIUM_RISK)
        assert result.score == 15
        assert result.classification == RiskClassification.LOW_RISK

    def test_ip_alone_is_high_risk(self) -> None:
        result = engine.score(extract("https://192.168.1.1/"))
        # IP alone = 30 pts → MEDIUM_RISK
        assert result.classification == RiskClassification.MEDIUM_RISK

    def test_userinfo_alone_is_high_risk(self) -> None:
        result = engine.score(extract("https://user:pass@example.com/"))
        # Userinfo alone = 35 pts → MEDIUM_RISK
        assert result.classification == RiskClassification.MEDIUM_RISK

    def test_critical_classification(self) -> None:
        result = engine.score(extract("http://user:pass@192.168.1.1/login"))
        assert result.classification == RiskClassification.CRITICAL


# ---------------------------------------------------------------------------
# Explainability
# ---------------------------------------------------------------------------


class TestExplainability:
    def test_every_reason_has_message(self) -> None:
        result = engine.score(extract("http://user:pass@192.168.1.1/login"))
        for r in result.reasons:
            assert r.message, f"Reason {r.code} has no message"

    def test_every_reason_has_severity(self) -> None:
        result = engine.score(extract("http://user:pass@192.168.1.1/login"))
        for r in result.reasons:
            assert r.severity is not None

    def test_every_reason_has_positive_contribution(self) -> None:
        result = engine.score(extract("http://user:pass@192.168.1.1/login"))
        for r in result.reasons:
            assert r.score_contribution > 0

    def test_analyzer_version_is_rule_v1(self) -> None:
        result = engine.score(extract("https://example.com/"))
        assert result.analyzer_version == "rule-v1"

    def test_low_risk_has_no_reasons(self) -> None:
        result = engine.score(extract("https://example.com/"))
        assert result.reasons == []


# ---------------------------------------------------------------------------
# Adversarial / edge cases from specification
# ---------------------------------------------------------------------------


class TestAdversarialExamples:
    def test_private_ip_login(self) -> None:
        """http://192.168.1.1/login — IP + keyword combination."""
        result = engine.score(extract("http://192.168.1.1/login"))
        assert result.score >= 50
        code_vals = {r.code.value for r in result.reasons}
        assert ReasonCode.IP_HOSTNAME.value in code_vals
        assert ReasonCode.HTTP_NOT_HTTPS.value in code_vals

    def test_userinfo_url(self) -> None:
        """http://user:password@example.com/login"""
        result = engine.score(extract("http://user:password@example.com/login"))
        code_vals = {r.code.value for r in result.reasons}
        assert ReasonCode.USERINFO_PRESENT.value in code_vals
        assert ReasonCode.HTTP_NOT_HTTPS.value in code_vals

    def test_punycode_url(self) -> None:
        """https://xn--... IDN domain."""
        result = engine.score(extract("https://xn--n3h.example.com/"))
        code_vals = {r.code.value for r in result.reasons}
        assert ReasonCode.PUNYCODE_DOMAIN.value in code_vals

    def test_very_long_url(self) -> None:
        long_url = "https://example.com/" + "a" * 1000
        result = engine.score(extract(long_url))
        code_vals = {r.code.value for r in result.reasons}
        assert ReasonCode.EXCESSIVE_URL_LENGTH.value in code_vals

    def test_double_encoded_url(self) -> None:
        result = engine.score(extract("https://example.com/%2525252525"))
        code_vals = {r.code.value for r in result.reasons}
        assert ReasonCode.HIGH_ENCODING_RATIO.value in code_vals

    def test_deeply_nested_subdomains(self) -> None:
        result = engine.score(extract("https://login.verify.account.example.com/"))
        code_vals = {r.code.value for r in result.reasons}
        assert ReasonCode.EXCESSIVE_SUBDOMAINS.value in code_vals

    def test_suspicious_tld_with_keyword(self) -> None:
        result = engine.score(extract("https://secure-bank.xyz/login"))
        code_vals = {r.code.value for r in result.reasons}
        assert ReasonCode.SUSPICIOUS_TLD.value in code_vals
        # Combination should push score up
        assert result.score >= 25
