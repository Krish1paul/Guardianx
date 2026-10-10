"""Message feature extraction — M7 Multi-Vector Threat Detection.

This module is pure and stateless: it accepts a message text (and optional
subject/sender) and returns a ``MessageFeatures`` dataclass. It performs NO I/O,
NO network requests, and NO external calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Lexical & Social Engineering Patterns
# ---------------------------------------------------------------------------

_URGENCY_PATTERNS = [
    r"\burgent\b",
    r"\bimmediat(e|ely)\b",
    r"\baction required\b",
    r"\bwithin 24 hours\b",
    r"\bwithin (12|48) hours\b",
    r"\bdeadline\b",
    r"\bexpires? (today|soon)\b",
    r"\blast chance\b",
    r"\btime[- ]sensitive\b",
    r"\bcritical notice\b",
    r"\bact now\b",
]

_CREDENTIAL_PATTERNS = [
    r"\bverif(y|ication)\b",
    r"\bconfirm your (account|password|identity|pin|ssn)\b",
    r"\bupdate your (account|password|credentials|login)\b",
    r"\breset your password\b",
    r"\blogin to (prevent|verify|restore|claim)\b",
    r"\benter your (credentials|passcode|passphrase|token)\b",
    r"\bsecurity code\b",
    r"\bone[- ]time (password|pin|code)\b",
    r"\b2fa\b",
]

_FINANCIAL_PATTERNS = [
    r"\bwire transfer\b",
    r"\bpayment (failed|declined|pending|overdue)\b",
    r"\bunauthorized (transaction|charge|activity)\b",
    r"\brefund (pending|approved|available)\b",
    r"\bcrypto(currency)?\b",
    r"\bbitcoin\b",
    r"\bbank account\b",
    r"\binvoice (attached|overdue|unpaid)\b",
    r"\bgift card\b",
    r"\bclaim your (prize|reward|cash)\b",
    r"\blottery\b",
    r"\bwon \$?[0-9,]+\b",
]

_SUSPENSION_PATTERNS = [
    r"\baccount (?:has been |is |was )?(?:suspended|locked|terminated|disabled|frozen)\b",
    r"\baccess (?:has been )?(?:revoked|denied|blocked)\b",
    r"\bsecurity breach\b",
    r"\bunusual activity detected\b",
    r"\bviolation of (?:policy|terms)\b",
    r"\bpermanently deleted?\b",
]

_IMPERSONATION_PATTERNS = [
    r"\bit support\b",
    r"\bhelp[- ]?desk\b",
    r"\bsecurity (?:team|operations|alert)\b",
    r"\badmin(?:istrator)?\b",
    r"\bhuman resources\b",
    r"\bpayroll\b",
    r"\bpaypal\b",
    r"\bmicrosoft (?:security|365|support)\b",
    r"\bapple (?:id|support)\b",
    r"\bgoogle (?:security|account)\b",
    r"\bnetflix\b",
    r"\bamazon (?:security|order|support)\b",
    r"\birs\b",
    r"\bfraud (?:department|prevention)\b",
]

_CALL_TO_ACTION_PATTERNS = [
    r"\bclick here\b",
    r"\bclick the link\b",
    r"\bdownload (?:the )?attachment\b",
    r"\bfollow the link\b",
    r"\bopen the attached\b",
    r"\bscan this qr\b",
    r"\bvisit this (?:site|url|page)\b",
]

_URL_REGEX = re.compile(
    r"https?://[^\s<>'\"`]+",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class MessageFeatures:
    """Structured features extracted deterministically from message text."""

    # Content length & structure
    char_count: int
    word_count: int
    uppercase_ratio: float
    exclamation_count: int
    question_count: int

    # Threat indicators count
    urgency_count: int
    credential_count: int
    financial_count: int
    suspension_count: int
    impersonation_count: int
    call_to_action_count: int

    # URL presence
    extracted_urls: list[str] = field(default_factory=list)
    url_count: int = 0

    # Metadata indicators
    has_suspicious_subject: bool = False
    has_suspicious_sender: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize features to dictionary."""
        return {
            "char_count": self.char_count,
            "word_count": self.word_count,
            "uppercase_ratio": round(self.uppercase_ratio, 4),
            "exclamation_count": self.exclamation_count,
            "question_count": self.question_count,
            "urgency_count": self.urgency_count,
            "credential_count": self.credential_count,
            "financial_count": self.financial_count,
            "suspension_count": self.suspension_count,
            "impersonation_count": self.impersonation_count,
            "call_to_action_count": self.call_to_action_count,
            "url_count": self.url_count,
            "extracted_urls": self.extracted_urls,
            "has_suspicious_subject": self.has_suspicious_subject,
            "has_suspicious_sender": self.has_suspicious_sender,
        }

    def feature_vector(self) -> list[float]:
        """Numeric vector for ML models / heuristic scoring."""
        return [
            float(self.char_count),
            float(self.word_count),
            self.uppercase_ratio,
            float(self.exclamation_count),
            float(self.question_count),
            float(self.urgency_count),
            float(self.credential_count),
            float(self.financial_count),
            float(self.suspension_count),
            float(self.impersonation_count),
            float(self.call_to_action_count),
            float(self.url_count),
            1.0 if self.has_suspicious_subject else 0.0,
            1.0 if self.has_suspicious_sender else 0.0,
        ]


def extract_message_features(
    message: str,
    subject: str | None = None,
    sender: str | None = None,
) -> MessageFeatures:
    """Extract structural and linguistic threat features from message text."""
    combined_text = message
    if subject:
        combined_text = f"{subject}\n{message}"

    char_count = len(message)
    words = combined_text.split()
    word_count = len(words)

    # Uppercase ratio
    alpha_chars = [c for c in combined_text if c.isalpha()]
    upper_chars = [c for c in alpha_chars if c.isupper()]
    uppercase_ratio = len(upper_chars) / len(alpha_chars) if alpha_chars else 0.0

    exclamation_count = combined_text.count("!")
    question_count = combined_text.count("?")

    # Regex matching
    text_lower = combined_text.lower()

    urgency_count = sum(1 for p in _URGENCY_PATTERNS if re.search(p, text_lower))
    credential_count = sum(1 for p in _CREDENTIAL_PATTERNS if re.search(p, text_lower))
    financial_count = sum(1 for p in _FINANCIAL_PATTERNS if re.search(p, text_lower))
    suspension_count = sum(1 for p in _SUSPENSION_PATTERNS if re.search(p, text_lower))
    impersonation_count = sum(1 for p in _IMPERSONATION_PATTERNS if re.search(p, text_lower))
    call_to_action_count = sum(1 for p in _CALL_TO_ACTION_PATTERNS if re.search(p, text_lower))

    # Safe URL extraction
    raw_urls = _URL_REGEX.findall(combined_text)
    seen_urls: set[str] = set()
    extracted_urls: list[str] = []
    for u in raw_urls:
        clean_u = u.rstrip(".,;!?'\")>")
        if clean_u and clean_u not in seen_urls:
            seen_urls.add(clean_u)
            extracted_urls.append(clean_u)

    # Suspicious subject / sender heuristics
    has_suspicious_subject = False
    if subject:
        sub_lower = subject.lower()
        if any(
            re.search(p, sub_lower)
            for p in (_URGENCY_PATTERNS + _SUSPENSION_PATTERNS + _FINANCIAL_PATTERNS)
        ):
            has_suspicious_subject = True

    has_suspicious_sender = False
    if sender:
        sender_lower = sender.lower()
        suspicious_sender_keywords = [
            "support",
            "admin",
            "security",
            "paypal",
            "bank",
            "apple",
            "account",
        ]
        suspicious_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]
        if any(kw in sender_lower for kw in suspicious_sender_keywords):
            if any(dom in sender_lower for dom in suspicious_domains):
                has_suspicious_sender = True

    return MessageFeatures(
        char_count=char_count,
        word_count=word_count,
        uppercase_ratio=uppercase_ratio,
        exclamation_count=exclamation_count,
        question_count=question_count,
        urgency_count=urgency_count,
        credential_count=credential_count,
        financial_count=financial_count,
        suspension_count=suspension_count,
        impersonation_count=impersonation_count,
        call_to_action_count=call_to_action_count,
        extracted_urls=extracted_urls,
        url_count=len(extracted_urls),
        has_suspicious_subject=has_suspicious_subject,
        has_suspicious_sender=has_suspicious_sender,
    )
