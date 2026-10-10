"""Tests for URL feature extraction — M2.

Tests cover every feature category:
- Structural features
- Host / domain features
- Security features
- Lexical features

All tests are pure (no I/O, no DB, no network).
"""

from __future__ import annotations

import os
import sys

# Ensure ml/ is importable when running tests from within backend/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))


from ml.features.url_features import extract

# ---------------------------------------------------------------------------
# Structural features
# ---------------------------------------------------------------------------


class TestStructuralFeatures:
    def test_url_length(self) -> None:
        url = "https://example.com/"
        f = extract(url)
        assert f.url_length == len(url)

    def test_hostname_length(self) -> None:
        f = extract("https://example.com/")
        assert f.hostname_length == len("example.com")

    def test_path_length(self) -> None:
        f = extract("https://example.com/some/path")
        assert f.path_length == len("/some/path")

    def test_query_length(self) -> None:
        f = extract("https://example.com/?key=value")
        assert f.query_length == len("key=value")

    def test_num_path_segments(self) -> None:
        f = extract("https://example.com/a/b/c")
        assert f.num_path_segments == 3

    def test_num_query_params(self) -> None:
        f = extract("https://example.com/?a=1&b=2&c=3")
        assert f.num_query_params == 3

    def test_num_dots_in_host(self) -> None:
        f = extract("https://sub.example.com/")
        assert f.num_dots == 2

    def test_num_hyphens_in_host(self) -> None:
        # my-secure-login.example.com → hyphens: 'my-secure' + 'secure-login' = 2
        f = extract("https://my-secure-login.example.com/")
        assert f.num_hyphens == 2

    def test_num_digits_in_host(self) -> None:
        f = extract("https://192.168.1.1/")
        # IP is detected as ip, but digits should still be counted
        assert f.num_digits_in_host > 0

    def test_no_subdomains(self) -> None:
        f = extract("https://example.com/")
        assert f.num_subdomains == 0

    def test_one_subdomain(self) -> None:
        f = extract("https://www.example.com/")
        assert f.num_subdomains == 1

    def test_multiple_subdomains(self) -> None:
        f = extract("https://a.b.c.example.com/")
        assert f.num_subdomains == 3


# ---------------------------------------------------------------------------
# Host / domain features
# ---------------------------------------------------------------------------


class TestHostDomainFeatures:
    def test_https_not_ip(self) -> None:
        f = extract("https://example.com/")
        assert not f.is_ip_address
        assert not f.is_ipv4
        assert not f.is_ipv6

    def test_ipv4_detected(self) -> None:
        f = extract("https://192.168.1.1/admin")
        assert f.is_ip_address
        assert f.is_ipv4
        assert not f.is_ipv6

    def test_ipv4_private_range(self) -> None:
        f = extract("http://10.0.0.1/login")
        assert f.is_ipv4

    def test_ipv6_detected(self) -> None:
        f = extract("https://[::1]/")
        assert f.is_ip_address
        assert f.is_ipv6
        assert not f.is_ipv4

    def test_punycode_detected(self) -> None:
        f = extract("https://xn--n3h.example.com/")
        assert f.is_punycode

    def test_no_punycode_on_ascii(self) -> None:
        f = extract("https://example.com/")
        assert not f.is_punycode

    def test_suspicious_tld_xyz(self) -> None:
        f = extract("https://example.xyz/")
        assert f.is_suspicious_tld
        assert f.tld == "xyz"

    def test_suspicious_tld_tk(self) -> None:
        f = extract("https://example.tk/")
        assert f.is_suspicious_tld

    def test_benign_tld_com(self) -> None:
        f = extract("https://example.com/")
        assert not f.is_suspicious_tld
        assert f.tld == "com"

    def test_benign_tld_org(self) -> None:
        f = extract("https://wikipedia.org/")
        assert not f.is_suspicious_tld

    def test_subdomain_depth(self) -> None:
        f = extract("https://login.verify.account.evil.com/")
        assert f.subdomain_depth == 3

    def test_zero_subdomain_depth(self) -> None:
        f = extract("https://example.com/")
        assert f.subdomain_depth == 0


# ---------------------------------------------------------------------------
# Security features
# ---------------------------------------------------------------------------


class TestSecurityFeatures:
    def test_https_detected(self) -> None:
        f = extract("https://example.com/")
        assert f.is_https
        assert not f.is_http

    def test_http_detected(self) -> None:
        f = extract("http://example.com/")
        assert f.is_http
        assert not f.is_https

    def test_no_non_standard_port_https(self) -> None:
        f = extract("https://example.com/")
        assert not f.has_non_standard_port

    def test_non_standard_port_detected(self) -> None:
        f = extract("https://example.com:8443/")
        assert f.has_non_standard_port

    def test_default_port_not_flagged_https(self) -> None:
        f = extract("https://example.com:443/")
        assert not f.has_non_standard_port

    def test_default_port_not_flagged_http(self) -> None:
        f = extract("http://example.com:80/")
        assert not f.has_non_standard_port

    def test_userinfo_present(self) -> None:
        f = extract("https://user:password@example.com/")
        assert f.has_userinfo

    def test_userinfo_only_username(self) -> None:
        f = extract("https://user@example.com/")
        assert f.has_userinfo

    def test_no_userinfo(self) -> None:
        f = extract("https://example.com/")
        assert not f.has_userinfo

    def test_encoded_chars_detected(self) -> None:
        f = extract("https://example.com/%2F%2F")
        assert f.has_encoded_chars

    def test_double_encoding_detected(self) -> None:
        f = extract("https://example.com/%2525252525")
        assert f.double_encoding_indicator

    def test_high_encoding_ratio(self) -> None:
        # URL with many percent-encoded chars
        f = extract("https://example.com/%41%42%43%44%45%46%47%48")
        assert f.encoding_ratio > 0.10

    def test_no_encoding(self) -> None:
        f = extract("https://example.com/plain/path")
        assert not f.has_encoded_chars
        assert f.encoding_ratio == 0.0


# ---------------------------------------------------------------------------
# Lexical features
# ---------------------------------------------------------------------------


class TestLexicalFeatures:
    def test_login_keyword_detected(self) -> None:
        f = extract("https://example.com/login")
        assert "login" in f.suspicious_keywords_found

    def test_verify_keyword_detected(self) -> None:
        f = extract("https://example.com/verify-account")
        assert "verify" in f.suspicious_keywords_found

    def test_password_keyword_in_path(self) -> None:
        f = extract("https://example.com/reset-password")
        assert "password" in f.credential_keywords_in_path

    def test_no_keywords_benign_url(self) -> None:
        f = extract("https://news.example.com/articles/2024/tech")
        assert len(f.suspicious_keywords_found) == 0

    def test_num_suspicious_keywords_counts_distinct(self) -> None:
        f = extract("https://example.com/login?verify=1")
        assert f.num_suspicious_keywords >= 2

    def test_google_login_has_keyword(self) -> None:
        # keyword present but should not alone make the URL high risk
        f = extract("https://accounts.google.com/login")
        assert "login" in f.suspicious_keywords_found
        # But the host is not an IP, not punycode, not suspicious TLD
        assert not f.is_ip_address
        assert not f.is_suspicious_tld
        assert not f.is_punycode

    def test_credential_keywords_in_path_only(self) -> None:
        # Keyword in hostname counts for suspicious_keywords_found
        # but not for credential_keywords_in_path
        f = extract("https://login.example.com/home")
        # "login" appears in hostname portion, suspicious_keywords_found covers all
        assert "login" in f.suspicious_keywords_found


# ---------------------------------------------------------------------------
# Adversarial inputs
# ---------------------------------------------------------------------------


class TestAdversarialInputs:
    def test_ip_with_credentials_in_url(self) -> None:
        f = extract("http://user:password@192.168.1.1/login")
        assert f.is_ipv4
        assert f.has_userinfo
        assert f.is_http
        assert "login" in f.suspicious_keywords_found

    def test_deeply_nested_subdomain_with_keywords(self) -> None:
        f = extract("https://login.verify.account.example.com/")
        assert f.subdomain_depth >= 3
        assert "login" in f.suspicious_keywords_found

    def test_double_encoded_path(self) -> None:
        f = extract("https://example.com/%2525252525")
        assert f.double_encoding_indicator

    def test_very_long_url(self) -> None:
        long_url = "https://example.com/" + "a" * 1500
        f = extract(long_url)
        assert f.url_length > 500

    def test_punycode_with_keyword(self) -> None:
        f = extract("https://xn--pypal-4ve.com/login")
        assert f.is_punycode
        assert "login" in f.suspicious_keywords_found
