"""Deterministic URL risk engine — M2.

This module scores URL risk based on weighted, combination-aware rules applied
to extracted ``URLFeatures``.  It is designed so that M3 can replace the
inference layer (``ml/inference/url_inference.py``) without touching the rule
engine itself — the rule engine remains available as a fallback and for
explainability purposes.

Design principles
-----------------
- **Deterministic**: same input → same output, always.
- **No network I/O**: pure computation over the feature dataclass.
- **Combination-aware**: individual signals score low; combinations score high.
  Example: "login" keyword alone: 5 pts.  "login" + IP hostname: 25 pts.
- **Explainable**: every score contribution is a structured ``RiskReason``.
- **Clamped**: final score is always in [0, 100].

Scoring thresholds
------------------
  0 –  24  →  LOW_RISK
 25 –  49  →  MEDIUM_RISK
 50 –  74  →  HIGH_RISK
 75 – 100  →  CRITICAL
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ml.features.url_features import URLFeatures

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RiskClassification(str, Enum):
    """Risk classification tier derived from the numeric score."""

    LOW_RISK = "LOW_RISK"
    MEDIUM_RISK = "MEDIUM_RISK"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"


class Severity(str, Enum):
    """Severity level of an individual risk reason."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ReasonCode(str, Enum):
    """Enumerated reason codes for risk explanations."""

    HTTP_NOT_HTTPS = "HTTP_NOT_HTTPS"
    IP_HOSTNAME = "IP_HOSTNAME"
    PUNYCODE_DOMAIN = "PUNYCODE_DOMAIN"
    EXCESSIVE_SUBDOMAINS = "EXCESSIVE_SUBDOMAINS"
    SUSPICIOUS_TLD = "SUSPICIOUS_TLD"
    SUSPICIOUS_KEYWORD = "SUSPICIOUS_KEYWORD"
    CREDENTIAL_PATH = "CREDENTIAL_PATH"
    USERINFO_PRESENT = "USERINFO_PRESENT"
    NON_STANDARD_PORT = "NON_STANDARD_PORT"
    EXCESSIVE_URL_LENGTH = "EXCESSIVE_URL_LENGTH"
    HIGH_ENCODING_RATIO = "HIGH_ENCODING_RATIO"
    SUSPICIOUS_COMBINATION = "SUSPICIOUS_COMBINATION"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RiskReason:
    """A single explainable risk reason contributing to the total score.

    Attributes
    ----------
    code:
        Machine-readable reason code (``ReasonCode`` enum value).
    severity:
        Human-readable severity level.
    message:
        Human-readable explanation of what was detected and why it matters.
    score_contribution:
        The number of points this reason contributed to the total score.
        Not exposed in the API response by default; available for debugging.
    """

    code: ReasonCode
    severity: Severity
    message: str
    score_contribution: int


@dataclass
class URLRiskResult:
    """Result produced by the ``URLRiskEngine``.

    Attributes
    ----------
    score:
        Clamped integer risk score in [0, 100].
    classification:
        Risk classification tier derived from ``score``.
    reasons:
        List of explainable reasons that contributed to the score.
    analyzer_version:
        Version string identifying which analyzer produced this result.
    """

    score: int
    classification: RiskClassification
    reasons: list[RiskReason] = field(default_factory=list)
    analyzer_version: str = "rule-v1"


# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

_THRESHOLDS = [
    (75, RiskClassification.CRITICAL),
    (50, RiskClassification.HIGH_RISK),
    (25, RiskClassification.MEDIUM_RISK),
    (0, RiskClassification.LOW_RISK),
]


def _classify(score: int) -> RiskClassification:
    for threshold, classification in _THRESHOLDS:
        if score >= threshold:
            return classification
    return RiskClassification.LOW_RISK  # unreachable but satisfies type checker


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------


class URLRiskEngine:
    """Deterministic, stateless URL risk scorer.

    Usage::

        engine = URLRiskEngine()
        result = engine.score(features)

    The engine is stateless and thread-safe.  A single instance may be
    reused across requests.
    """

    ANALYZER_VERSION = "rule-v1"

    def score(self, features: URLFeatures) -> URLRiskResult:
        """Score a URL given its extracted feature set.

        Parameters
        ----------
        features:
            Pre-computed ``URLFeatures`` from ``url_features.extract()``.

        Returns
        -------
        URLRiskResult:
            Contains the clamped score, classification, and explainable reasons.
        """
        reasons: list[RiskReason] = []

        # ------------------------------------------------------------------ #
        # Rule 1 — HTTP (not HTTPS)                                           #
        # ------------------------------------------------------------------ #
        if features.is_http:
            reasons.append(
                RiskReason(
                    code=ReasonCode.HTTP_NOT_HTTPS,
                    severity=Severity.MEDIUM,
                    message=(
                        "The URL uses HTTP instead of HTTPS.  Traffic over HTTP "
                        "is transmitted in plaintext and can be intercepted or "
                        "modified by a network attacker (man-in-the-middle)."
                    ),
                    score_contribution=15,
                )
            )

        # ------------------------------------------------------------------ #
        # Rule 2 — IP address hostname                                        #
        # ------------------------------------------------------------------ #
        if features.is_ip_address:
            reasons.append(
                RiskReason(
                    code=ReasonCode.IP_HOSTNAME,
                    severity=Severity.HIGH,
                    message=(
                        "The URL uses a raw IP address instead of a domain name.  "
                        "Legitimate services almost always use registered domain names.  "
                        "IP-based URLs are commonly used in phishing and malware campaigns "
                        "to avoid domain reputation checks."
                    ),
                    score_contribution=30,
                )
            )

        # ------------------------------------------------------------------ #
        # Rule 3 — Punycode / IDN domain                                     #
        # ------------------------------------------------------------------ #
        if features.is_punycode:
            reasons.append(
                RiskReason(
                    code=ReasonCode.PUNYCODE_DOMAIN,
                    severity=Severity.HIGH,
                    message=(
                        "The URL contains a Punycode-encoded (xn--) internationalized "
                        "domain name.  IDN homograph attacks use visually similar "
                        "Unicode characters to impersonate legitimate domains "
                        "(e.g. аpple.com using a Cyrillic 'а' instead of Latin 'a')."
                    ),
                    score_contribution=25,
                )
            )

        # ------------------------------------------------------------------ #
        # Rule 4 — Excessive subdomains                                      #
        # ------------------------------------------------------------------ #
        if features.subdomain_depth >= 4:
            reasons.append(
                RiskReason(
                    code=ReasonCode.EXCESSIVE_SUBDOMAINS,
                    severity=Severity.MEDIUM,
                    message=(
                        f"The hostname has {features.subdomain_depth} subdomain levels "
                        f"(e.g. a.b.c.d.example.com).  Deeply nested subdomains are "
                        "sometimes used to disguise the true registered domain and make "
                        "URLs appear to belong to a legitimate site."
                    ),
                    score_contribution=20,
                )
            )
        elif features.subdomain_depth >= 2:
            reasons.append(
                RiskReason(
                    code=ReasonCode.EXCESSIVE_SUBDOMAINS,
                    severity=Severity.LOW,
                    message=(
                        f"The hostname has {features.subdomain_depth} subdomain levels.  "
                        "Unusual subdomain depth can be used to mislead users about the "
                        "true ownership of a domain."
                    ),
                    score_contribution=8,
                )
            )

        # ------------------------------------------------------------------ #
        # Rule 5 — Suspicious TLD                                            #
        # ------------------------------------------------------------------ #
        if features.is_suspicious_tld:
            reasons.append(
                RiskReason(
                    code=ReasonCode.SUSPICIOUS_TLD,
                    severity=Severity.MEDIUM,
                    message=(
                        f"The top-level domain '.{features.tld}' is associated with "
                        "high abuse rates.  Free or low-cost TLDs are frequently used "
                        "in phishing campaigns because domains can be registered cheaply "
                        "and discarded quickly."
                    ),
                    score_contribution=20,
                )
            )

        # ------------------------------------------------------------------ #
        # Rule 6 — Userinfo present (user:password@ in URL)                 #
        # ------------------------------------------------------------------ #
        if features.has_userinfo:
            reasons.append(
                RiskReason(
                    code=ReasonCode.USERINFO_PRESENT,
                    severity=Severity.CRITICAL,
                    message=(
                        "The URL contains a userinfo component (user:password@ or user@).  "
                        "This syntax is rarely used by legitimate services and is a "
                        "well-known phishing technique: the username portion can be set "
                        "to a trusted domain name to confuse users about the real "
                        "destination (e.g. https://paypal.com@evil.com/login)."
                    ),
                    score_contribution=35,
                )
            )

        # ------------------------------------------------------------------ #
        # Rule 7 — Non-standard port                                         #
        # ------------------------------------------------------------------ #
        if features.has_non_standard_port:
            reasons.append(
                RiskReason(
                    code=ReasonCode.NON_STANDARD_PORT,
                    severity=Severity.LOW,
                    message=(
                        "The URL specifies a non-standard port number.  While this is "
                        "sometimes legitimate (development servers, self-hosted services), "
                        "it can also indicate an attacker-controlled service running on "
                        "an uncommon port to evade network-level filtering."
                    ),
                    score_contribution=10,
                )
            )

        # ------------------------------------------------------------------ #
        # Rule 8 — Excessive URL length                                      #
        # ------------------------------------------------------------------ #
        if features.url_length > 500:
            reasons.append(
                RiskReason(
                    code=ReasonCode.EXCESSIVE_URL_LENGTH,
                    severity=Severity.MEDIUM,
                    message=(
                        f"The URL is {features.url_length} characters long.  "
                        "Extremely long URLs are sometimes used to obfuscate the true "
                        "destination, overflow URL-length limits in security tools, or "
                        "hide embedded payloads in query parameters."
                    ),
                    score_contribution=15,
                )
            )
        elif features.url_length > 200:
            reasons.append(
                RiskReason(
                    code=ReasonCode.EXCESSIVE_URL_LENGTH,
                    severity=Severity.LOW,
                    message=(
                        f"The URL is {features.url_length} characters long.  "
                        "URLs significantly longer than typical may be used to "
                        "obscure the true destination."
                    ),
                    score_contribution=5,
                )
            )

        # ------------------------------------------------------------------ #
        # Rule 9 — High encoding ratio / double encoding                    #
        # ------------------------------------------------------------------ #
        if features.double_encoding_indicator:
            reasons.append(
                RiskReason(
                    code=ReasonCode.HIGH_ENCODING_RATIO,
                    severity=Severity.HIGH,
                    message=(
                        "The URL contains double percent-encoding (%25xx).  "
                        "This technique is used to bypass URL-based security filters "
                        "by encoding the percent sign itself, causing servers or security "
                        "tools to decode the URL in multiple passes."
                    ),
                    score_contribution=25,
                )
            )
        elif features.encoding_ratio > 0.20:
            reasons.append(
                RiskReason(
                    code=ReasonCode.HIGH_ENCODING_RATIO,
                    severity=Severity.MEDIUM,
                    message=(
                        f"The URL has a high percent-encoding ratio "
                        f"({features.encoding_ratio:.0%}).  "
                        "Excessive URL encoding can obscure the true content of a URL "
                        "and is sometimes used to evade content-based security filters."
                    ),
                    score_contribution=20,
                )
            )
        elif features.encoding_ratio > 0.10:
            reasons.append(
                RiskReason(
                    code=ReasonCode.HIGH_ENCODING_RATIO,
                    severity=Severity.LOW,
                    message=(
                        f"The URL contains a notable amount of percent-encoding "
                        f"({features.encoding_ratio:.0%}).  "
                        "While encoding is valid, unusually high ratios may warrant "
                        "additional scrutiny."
                    ),
                    score_contribution=8,
                )
            )

        # ------------------------------------------------------------------ #
        # Rule 10 — Credential-related path on unusual host                 #
        # ------------------------------------------------------------------ #
        has_cred_path = len(features.credential_keywords_in_path) > 0
        unusual_host = (
            features.is_ip_address
            or features.is_punycode
            or features.is_suspicious_tld
            or features.has_userinfo
        )
        if has_cred_path and unusual_host:
            reasons.append(
                RiskReason(
                    code=ReasonCode.CREDENTIAL_PATH,
                    severity=Severity.HIGH,
                    message=(
                        "The URL path contains credential-related terms "
                        f"({', '.join(features.credential_keywords_in_path)}) "
                        "combined with an unusual hostname characteristic.  "
                        "This combination is a strong phishing indicator: credential "
                        "collection pages hosted on suspicious infrastructure."
                    ),
                    score_contribution=20,
                )
            )
        elif has_cred_path and features.is_http:
            reasons.append(
                RiskReason(
                    code=ReasonCode.CREDENTIAL_PATH,
                    severity=Severity.MEDIUM,
                    message=(
                        "The URL path contains credential-related terms "
                        f"({', '.join(features.credential_keywords_in_path)}) "
                        "on a non-HTTPS connection.  Submitting credentials over HTTP "
                        "exposes them to network eavesdropping."
                    ),
                    score_contribution=12,
                )
            )

        # ------------------------------------------------------------------ #
        # Rule 11 — Suspicious keyword combinations                         #
        # ------------------------------------------------------------------ #
        has_keywords = features.num_suspicious_keywords > 0

        if has_keywords and features.is_ip_address:
            reasons.append(
                RiskReason(
                    code=ReasonCode.SUSPICIOUS_COMBINATION,
                    severity=Severity.HIGH,
                    message=(
                        "The URL combines suspicious keyword(s) "
                        f"({', '.join(features.suspicious_keywords_found[:3])}) "
                        "with an IP address hostname.  This combination is strongly "
                        "associated with phishing pages impersonating login portals "
                        "of legitimate services."
                    ),
                    score_contribution=20,
                )
            )

        if has_keywords and features.is_punycode:
            reasons.append(
                RiskReason(
                    code=ReasonCode.SUSPICIOUS_COMBINATION,
                    severity=Severity.HIGH,
                    message=(
                        "The URL combines suspicious keyword(s) "
                        f"({', '.join(features.suspicious_keywords_found[:3])}) "
                        "with a Punycode-encoded domain.  This is a common pattern "
                        "in IDN homograph phishing attacks targeting account takeover."
                    ),
                    score_contribution=15,
                )
            )

        if has_keywords and features.is_http:
            reasons.append(
                RiskReason(
                    code=ReasonCode.SUSPICIOUS_COMBINATION,
                    severity=Severity.MEDIUM,
                    message=(
                        "The URL combines suspicious keyword(s) "
                        f"({', '.join(features.suspicious_keywords_found[:3])}) "
                        "with an unencrypted HTTP connection.  Sensitive actions "
                        "(login, account verification) should always be performed "
                        "over HTTPS."
                    ),
                    score_contribution=10,
                )
            )

        if has_keywords and features.subdomain_depth >= 3:
            reasons.append(
                RiskReason(
                    code=ReasonCode.SUSPICIOUS_COMBINATION,
                    severity=Severity.MEDIUM,
                    message=(
                        "The URL combines suspicious keyword(s) "
                        f"({', '.join(features.suspicious_keywords_found[:3])}) "
                        "with an unusually deep subdomain structure "
                        f"({features.subdomain_depth} levels).  "
                        "This pattern is used to make the URL appear to belong to a "
                        "legitimate service while the true registered domain is different."
                    ),
                    score_contribution=12,
                )
            )

        # ------------------------------------------------------------------ #
        # Rule 12 — Standalone suspicious keywords (low weight, low FP)     #
        # ------------------------------------------------------------------ #
        # Only applied when NO high-weight rule already fired to avoid         #
        # double-counting signals.  Weight is intentionally tiny (5 pts max) #
        # to avoid false positives on legitimate URLs like google.com/login. #
        has_high_weight_reason = any(
            r.score_contribution >= 15 for r in reasons
        )
        if has_keywords and not has_high_weight_reason:
            reasons.append(
                RiskReason(
                    code=ReasonCode.SUSPICIOUS_KEYWORD,
                    severity=Severity.LOW,
                    message=(
                        "The URL contains terms commonly found in phishing URLs "
                        f"({', '.join(features.suspicious_keywords_found[:5])}).  "
                        "Note: these keywords alone are not sufficient to classify a URL "
                        "as malicious — many legitimate sites use these terms."
                    ),
                    score_contribution=5,
                )
            )

        # ------------------------------------------------------------------ #
        # Final scoring
        # ------------------------------------------------------------------ #
        raw_score = sum(r.score_contribution for r in reasons)
        clamped_score = max(0, min(100, raw_score))
        classification = _classify(clamped_score)

        return URLRiskResult(
            score=clamped_score,
            classification=classification,
            reasons=reasons,
            analyzer_version=self.ANALYZER_VERSION,
        )
