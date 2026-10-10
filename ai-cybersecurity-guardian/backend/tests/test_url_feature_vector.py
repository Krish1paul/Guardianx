"""Tests for url_feature_vector — stable numeric feature schema.

Verifies:
- FEATURE_NAMES and FEATURE_COUNT are stable
- features_to_vector() produces the correct length
- Boolean features encode to 0.0 / 1.0
- Known URL → known feature values
- Feature order matches FEATURE_NAMES
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from ml.features import url_features  # noqa: E402
from ml.features.url_feature_vector import (  # noqa: E402
    FEATURE_COUNT,
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    features_to_vector,
)


class TestFeatureNames:
    def test_feature_names_is_list_of_strings(self) -> None:
        assert isinstance(FEATURE_NAMES, list)
        assert all(isinstance(n, str) for n in FEATURE_NAMES)

    def test_feature_count_matches_names_length(self) -> None:
        assert len(FEATURE_NAMES) == FEATURE_COUNT

    def test_feature_count_is_positive(self) -> None:
        assert FEATURE_COUNT > 0

    def test_schema_version_is_string(self) -> None:
        assert isinstance(FEATURE_SCHEMA_VERSION, str)
        assert FEATURE_SCHEMA_VERSION

    def test_no_duplicate_feature_names(self) -> None:
        assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))

    def test_known_features_present(self) -> None:
        expected = {
            "url_length", "hostname_length", "is_ip_address", "is_https",
            "is_http", "has_userinfo", "num_suspicious_keywords",
            "is_suspicious_tld", "is_punycode",
        }
        assert expected.issubset(set(FEATURE_NAMES))


class TestFeaturesToVector:
    def test_vector_length_matches_feature_count(self) -> None:
        f = url_features.extract("https://example.com/")
        v = features_to_vector(f)
        assert len(v) == FEATURE_COUNT

    def test_all_elements_are_float(self) -> None:
        f = url_features.extract("https://example.com/")
        v = features_to_vector(f)
        assert all(isinstance(x, float) for x in v)

    def test_boolean_is_https_encodes_true(self) -> None:
        f = url_features.extract("https://example.com/")
        v = features_to_vector(f)
        idx = FEATURE_NAMES.index("is_https")
        assert v[idx] == 1.0

    def test_boolean_is_https_encodes_false(self) -> None:
        f = url_features.extract("http://example.com/")
        v = features_to_vector(f)
        idx = FEATURE_NAMES.index("is_https")
        assert v[idx] == 0.0

    def test_boolean_is_http_encodes_correctly(self) -> None:
        f = url_features.extract("http://example.com/")
        v = features_to_vector(f)
        idx = FEATURE_NAMES.index("is_http")
        assert v[idx] == 1.0

    def test_is_ip_address_for_ip_url(self) -> None:
        f = url_features.extract("https://192.168.1.1/")
        v = features_to_vector(f)
        idx = FEATURE_NAMES.index("is_ip_address")
        assert v[idx] == 1.0

    def test_is_ip_address_for_domain_url(self) -> None:
        f = url_features.extract("https://example.com/")
        v = features_to_vector(f)
        idx = FEATURE_NAMES.index("is_ip_address")
        assert v[idx] == 0.0

    def test_url_length_is_correct(self) -> None:
        url = "https://example.com/"
        f = url_features.extract(url)
        v = features_to_vector(f)
        idx = FEATURE_NAMES.index("url_length")
        assert v[idx] == float(len(url))

    def test_num_suspicious_keywords_count(self) -> None:
        f = url_features.extract("https://example.com/login")
        v = features_to_vector(f)
        idx = FEATURE_NAMES.index("num_suspicious_keywords")
        assert v[idx] >= 1.0

    def test_has_userinfo_encoded_true(self) -> None:
        f = url_features.extract("https://user:pass@example.com/")
        v = features_to_vector(f)
        idx = FEATURE_NAMES.index("has_userinfo")
        assert v[idx] == 1.0

    def test_has_userinfo_encoded_false(self) -> None:
        f = url_features.extract("https://example.com/")
        v = features_to_vector(f)
        idx = FEATURE_NAMES.index("has_userinfo")
        assert v[idx] == 0.0

    def test_deterministic_same_url_same_vector(self) -> None:
        url = "https://example.com/path?q=1"
        v1 = features_to_vector(url_features.extract(url))
        v2 = features_to_vector(url_features.extract(url))
        assert v1 == v2

    def test_num_credential_keywords_in_path(self) -> None:
        f = url_features.extract("https://evil.xyz/login")
        v = features_to_vector(f)
        idx = FEATURE_NAMES.index("num_credential_keywords_in_path")
        assert v[idx] >= 1.0

    def test_benign_url_low_feature_values(self) -> None:
        f = url_features.extract("https://example.com/")
        v = features_to_vector(f)
        # All boolean risk flags should be 0
        for name in ("is_ip_address", "is_suspicious_tld", "is_punycode",
                     "has_userinfo", "double_encoding_indicator"):
            idx = FEATURE_NAMES.index(name)
            assert v[idx] == 0.0, f"Expected 0.0 for {name}"
