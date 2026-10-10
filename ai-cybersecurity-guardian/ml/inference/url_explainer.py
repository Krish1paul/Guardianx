"""URL threat explainability — M3.

Converts ML model feature importances into human-readable security reasons
that match the existing ``RiskReason`` / ``ReasonCode`` / ``Severity`` schema
defined in ``ml/features/url_risk_engine.py``.

Design
------
For tree-based models (Random Forest, XGBoost), feature importance is
extracted from ``model.named_steps['clf'].feature_importances_``.
For Logistic Regression, the absolute value of coefficients is used.

The explainer maps feature names to pre-defined security reason templates.
A reason is only emitted if:

1. The feature's importance is in the top-K features AND
2. The feature's **actual value** in the submitted URL is non-default
   (i.e. the feature meaningfully contributes to the prediction).

This avoids emitting reasons like "IP address detected" for a URL that
is not an IP address.

The output is a ``list[RiskReason]`` using the existing enum types — no
new API contract is introduced.

Security note
-------------
No I/O.  Pure computation over feature values and model metadata.
"""

from __future__ import annotations

import os
import sys
from typing import Any

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from ml.features.url_feature_vector import FEATURE_NAMES  # noqa: E402
from ml.features.url_features import URLFeatures  # noqa: E402
from ml.features.url_risk_engine import ReasonCode, RiskReason, Severity  # noqa: E402

# ---------------------------------------------------------------------------
# Top-K features to consider for explanations
# ---------------------------------------------------------------------------

_TOP_K: int = 8

# ---------------------------------------------------------------------------
# Feature → reason template mapping
# ---------------------------------------------------------------------------
# Maps a feature name to a (ReasonCode, Severity, message_template) tuple.
# Only features in this dict can produce explanations.

_FEATURE_REASONS: dict[str, tuple[ReasonCode, Severity, str]] = {
    "is_ip_address": (
        ReasonCode.IP_HOSTNAME,
        Severity.HIGH,
        "Hostname is a raw IP address — legitimate services rarely use IP-based URLs.",
    ),
    "is_ipv4": (
        ReasonCode.IP_HOSTNAME,
        Severity.HIGH,
        "Hostname is an IPv4 address — phishing pages frequently use IP-based URLs to avoid DNS.",
    ),
    "is_ipv6": (
        ReasonCode.IP_HOSTNAME,
        Severity.HIGH,
        "Hostname is an IPv6 address — unusual for legitimate web services.",
    ),
    "is_punycode": (
        ReasonCode.PUNYCODE_DOMAIN,
        Severity.HIGH,
        "Hostname contains a Punycode label (xn--) — may be a homograph phishing domain.",
    ),
    "is_suspicious_tld": (
        ReasonCode.SUSPICIOUS_TLD,
        Severity.MEDIUM,
        "Top-level domain is associated with a high rate of abuse and phishing.",
    ),
    "has_userinfo": (
        ReasonCode.USERINFO_PRESENT,
        Severity.HIGH,
        "URL contains user credentials (user:password@host) — common in phishing URLs.",
    ),
    "has_non_standard_port": (
        ReasonCode.NON_STANDARD_PORT,
        Severity.MEDIUM,
        "URL uses a non-standard port — legitimate HTTPS/HTTP services rarely deviate from 443/80.",
    ),
    "double_encoding_indicator": (
        ReasonCode.SUSPICIOUS_COMBINATION,
        Severity.HIGH,
        "URL contains double-encoded characters (%25) — common obfuscation technique.",
    ),
    "is_http": (
        ReasonCode.HTTP_NOT_HTTPS,
        Severity.LOW,
        "URL uses HTTP (not HTTPS) — connection is unencrypted and vulnerable to interception.",
    ),
    "num_suspicious_keywords": (
        ReasonCode.SUSPICIOUS_KEYWORD,
        Severity.MEDIUM,
        "URL contains terms commonly found in phishing and credential-harvesting pages.",
    ),
    "num_credential_keywords_in_path": (
        ReasonCode.CREDENTIAL_PATH,
        Severity.HIGH,
        "URL path contains credential-related keywords (login, password, auth, signin).",
    ),
    "subdomain_depth": (
        ReasonCode.EXCESSIVE_SUBDOMAINS,
        Severity.MEDIUM,
        "URL has an unusually large number of subdomain labels — possible subdomain abuse.",
    ),
    "url_length": (
        ReasonCode.EXCESSIVE_URL_LENGTH,
        Severity.LOW,
        "URL is excessively long — adversarial URLs are often padded to obscure the hostname.",
    ),
    "encoding_ratio": (
        ReasonCode.HIGH_ENCODING_RATIO,
        Severity.MEDIUM,
        "A significant fraction of the URL is percent-encoded — may indicate obfuscation.",
    ),
}


# Minimum feature value to consider "active" (avoids emitting reason for zero-value features)
_ACTIVE_THRESHOLDS: dict[str, float] = {
    "num_suspicious_keywords": 1.0,
    "num_credential_keywords_in_path": 1.0,
    "subdomain_depth": 3.0,  # only flag if >= 3 subdomains
    "url_length": 150.0,     # only flag if unusually long
    "encoding_ratio": 0.15,  # only flag if >15% encoded
}


def _is_feature_active(name: str, value: float) -> bool:
    """Return True if the feature value is meaningfully non-default."""
    threshold = _ACTIVE_THRESHOLDS.get(name, 0.5)  # default: boolean > 0.5
    return value > threshold


class URLExplainer:
    """Maps feature importances to human-readable RiskReason objects.

    Usage::

        explainer = URLExplainer(feature_importances)
        reasons = explainer.explain(features, probability)
    """

    def __init__(self, feature_importances: list[float] | None = None) -> None:
        """Initialise the explainer.

        Parameters
        ----------
        feature_importances:
            Optional list of per-feature importance scores in the same order
            as ``FEATURE_NAMES``.  If ``None``, falls back to uniform
            importance (all features treated equally).
        """
        if feature_importances is not None:
            if len(feature_importances) != len(FEATURE_NAMES):
                raise ValueError(
                    f"feature_importances length {len(feature_importances)} "
                    f"!= FEATURE_NAMES length {len(FEATURE_NAMES)}"
                )
            self._importances: list[float] = list(feature_importances)
        else:
            # Uniform: every feature gets equal weight
            self._importances = [1.0 / len(FEATURE_NAMES)] * len(FEATURE_NAMES)

    @classmethod
    def from_pipeline(cls, model: Any) -> "URLExplainer":
        """Construct an explainer from a trained sklearn Pipeline.

        Supports:
        - ``RandomForestClassifier`` / ``GradientBoostingClassifier`` via
          ``feature_importances_``
        - ``LogisticRegression`` via absolute coefficient values
        - ``XGBClassifier`` via ``feature_importances_``

        Falls back to uniform importances if the underlying estimator is
        not recognised.

        Parameters
        ----------
        model:
            A fitted sklearn Pipeline with a ``clf`` step.
        """
        importances: list[float] | None = None
        try:
            clf = model.named_steps["clf"]  # type: ignore[union-attr]
            if hasattr(clf, "feature_importances_"):
                importances = list(clf.feature_importances_.tolist())
            elif hasattr(clf, "coef_"):
                # Logistic Regression — use absolute coefficient as importance proxy
                coef = clf.coef_[0]
                abs_coef = [abs(c) for c in coef.tolist()]
                total = sum(abs_coef) or 1.0
                importances = [c / total for c in abs_coef]
        except (AttributeError, KeyError, IndexError):
            pass  # Uniform fallback
        return cls(importances)

    def explain(
        self,
        features: URLFeatures,
        probability: float,
    ) -> list[RiskReason]:
        """Generate explainable reasons from URL features.

        Parameters
        ----------
        features:
            Extracted ``URLFeatures`` for the URL being analyzed.
        probability:
            Malicious probability from the ML model (0.0–1.0).
            Used to gate whether any reasons are emitted at all.

        Returns
        -------
        list[RiskReason]:
            Ordered list of security reasons (highest contributing features
            first), or an empty list if the probability is low or no
            active features qualify.
        """
        # If probability is below 0.25, don't emit reasons (low-risk signal)
        if probability < 0.25:
            return []

        # Rank features by importance
        ranked = sorted(
            enumerate(self._importances),
            key=lambda x: x[1],
            reverse=True,
        )

        # Build feature vector for the current URL (for active-value checks)
        from ml.features.url_feature_vector import features_to_vector  # local import avoids cycle
        vector = features_to_vector(features)

        reasons: list[RiskReason] = []
        for idx, importance in ranked[:_TOP_K]:
            if idx >= len(FEATURE_NAMES):
                continue
            feature_name = FEATURE_NAMES[idx]
            if feature_name not in _FEATURE_REASONS:
                continue
            feature_value = vector[idx]
            if not _is_feature_active(feature_name, feature_value):
                continue

            code, severity, message = _FEATURE_REASONS[feature_name]
            reasons.append(
                RiskReason(
                    code=code,
                    severity=severity,
                    message=message,
                    score_contribution=max(1, round(importance * 100)),
                )
            )

        # Deduplicate by ReasonCode (a feature may map to the same code)
        seen_codes: set[ReasonCode] = set()
        deduped: list[RiskReason] = []
        for r in reasons:
            if r.code not in seen_codes:
                seen_codes.add(r.code)
                deduped.append(r)

        return deduped
