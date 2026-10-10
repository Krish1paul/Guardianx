"""Stable numeric feature vector for URL threat classification — M3.

This module defines the **single source of truth** for which URLFeatures
fields are included in the ML feature matrix and in what order.

Design intent
-------------
- ``FEATURE_NAMES`` is the authoritative ordered list of feature column names.
- ``features_to_vector()`` maps a ``URLFeatures`` instance to a ``list[float]``
  in exactly the same order as ``FEATURE_NAMES``.
- The same function is used during **training** and **production inference** so
  the feature pipeline is always identical.
- ``FEATURE_SCHEMA_VERSION`` must be bumped any time ``FEATURE_NAMES`` changes.
  The inference engine validates this against the saved model metadata to
  prevent silent mismatches.

Excluded fields
---------------
- ``raw_url``                   — identity string, not a feature
- ``tld``                       — categorical string; ``is_suspicious_tld`` captures the risk
- ``registered_domain``         — categorical string; structural features capture the risk
- ``suspicious_keywords_found`` — tuple of strings; ``num_suspicious_keywords`` is the count
- ``credential_keywords_in_path`` — tuple; ``num_credential_keywords_in_path`` is the count

Boolean encoding
----------------
``True`` → ``1.0``, ``False`` → ``0.0``

Security note
-------------
This module contains no I/O.  It is a pure data transformation function.
"""

from __future__ import annotations

import os
import sys

# Make ml package importable when imported from repo root or from backend/
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from ml.features.url_features import URLFeatures  # noqa: E402

# ---------------------------------------------------------------------------
# Feature schema version
# ---------------------------------------------------------------------------

#: Bump this any time FEATURE_NAMES changes.  The training pipeline records
#: this in metadata.json and the inference engine validates it at load time.
FEATURE_SCHEMA_VERSION: str = "v1"

# ---------------------------------------------------------------------------
# Ordered feature list — the ML model's column schema
# ---------------------------------------------------------------------------

FEATURE_NAMES: list[str] = [
    # Structural
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "num_path_segments",
    "num_query_params",
    "num_subdomains",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_digits_in_host",
    "num_special_chars_in_path",
    # Host / domain
    "is_ip_address",        # bool → 0/1
    "is_ipv4",              # bool → 0/1
    "is_ipv6",              # bool → 0/1
    "subdomain_depth",
    "is_suspicious_tld",    # bool → 0/1
    "is_punycode",          # bool → 0/1
    # Security
    "is_https",             # bool → 0/1
    "is_http",              # bool → 0/1
    "has_non_standard_port",  # bool → 0/1
    "has_userinfo",          # bool → 0/1
    "has_encoded_chars",     # bool → 0/1
    "double_encoding_indicator",  # bool → 0/1
    "encoding_ratio",        # float
    # Lexical (numeric counts — strings excluded)
    "num_suspicious_keywords",
    "num_credential_keywords_in_path",
]

#: Stable count for assertion checks.
FEATURE_COUNT: int = len(FEATURE_NAMES)


# ---------------------------------------------------------------------------
# Conversion function
# ---------------------------------------------------------------------------


def features_to_vector(f: URLFeatures) -> list[float]:
    """Convert a ``URLFeatures`` instance to a numeric feature vector.

    Parameters
    ----------
    f:
        A populated ``URLFeatures`` dataclass (from ``url_features.extract()``).

    Returns
    -------
    list[float]:
        A float vector of length ``FEATURE_COUNT`` in the same order as
        ``FEATURE_NAMES``.  Can be passed directly to scikit-learn
        ``predict()`` / ``predict_proba()`` after being wrapped in a 2D array.

    Notes
    -----
    Boolean fields are encoded as ``1.0`` (True) or ``0.0`` (False).
    All integer fields are cast to ``float``.
    ``encoding_ratio`` is already a float.
    """
    return [
        # Structural
        float(f.url_length),
        float(f.hostname_length),
        float(f.path_length),
        float(f.query_length),
        float(f.fragment_length),
        float(f.num_path_segments),
        float(f.num_query_params),
        float(f.num_subdomains),
        float(f.num_dots),
        float(f.num_hyphens),
        float(f.num_underscores),
        float(f.num_digits_in_host),
        float(f.num_special_chars_in_path),
        # Host / domain
        1.0 if f.is_ip_address else 0.0,
        1.0 if f.is_ipv4 else 0.0,
        1.0 if f.is_ipv6 else 0.0,
        float(f.subdomain_depth),
        1.0 if f.is_suspicious_tld else 0.0,
        1.0 if f.is_punycode else 0.0,
        # Security
        1.0 if f.is_https else 0.0,
        1.0 if f.is_http else 0.0,
        1.0 if f.has_non_standard_port else 0.0,
        1.0 if f.has_userinfo else 0.0,
        1.0 if f.has_encoded_chars else 0.0,
        1.0 if f.double_encoding_indicator else 0.0,
        float(f.encoding_ratio),
        # Lexical
        float(f.num_suspicious_keywords),
        float(len(f.credential_keywords_in_path)),
    ]
