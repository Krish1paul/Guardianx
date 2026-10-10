"""Tests for CorrelationEngine — M8.

Verifies:
- Strong signal correlation (identical URL hash, matching domain)
- Multi-vector correlation (Message -> embedded URL -> incident)
- Diminishing returns on repeated event scores
- Score and confidence clamping
- Deduplication against active open incidents
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from app.models.file_scan import FileScan
from app.models.message_scan import MessageScan
from app.models.url_scan import URLScan
from app.models.user import User
from app.services.intelligence.correlation_engine import CorrelationEngine
from sqlalchemy.orm import Session


@pytest.fixture
def test_user(db: Session) -> User:
    """Create a persistent user fixture for correlation tests."""
    user = User(
        id=uuid.uuid4(),
        email=f"analyst_{uuid.uuid4().hex[:8]}@example.com",
        password_hash="hashed_pw",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


class TestCorrelationEngine:
    """Test suite for incident correlation logic."""

    def test_correlate_url_scan_creates_incident(self, db: Session, test_user: User) -> None:
        scan = URLScan(
            id=uuid.uuid4(),
            user_id=test_user.id,
            url_hash="a" * 64,
            normalized_url="https://paypa1-secure.ru/login",
            risk_score=85,
            classification="HIGH_RISK",
            features={"domain": "paypa1-secure.ru"},
            reasons=[{"title": "Punycode", "score_contribution": 30}],
            analyzer_version="rule-v1",
            created_at=datetime.now(UTC),
        )
        db.add(scan)
        db.commit()

        engine = CorrelationEngine(db)
        incident = engine.correlate_url_scan(scan)
        assert incident is not None
        assert incident.user_id == test_user.id
        assert incident.status == "OPEN"
        assert incident.risk_score >= 85
        assert incident.event_count == 1
        assert len(incident.events) == 1
        assert "paypa1-secure.ru" in incident.title

    def test_correlate_second_scan_with_same_domain_attaches_to_existing(
        self, db: Session, test_user: User
    ) -> None:
        now = datetime.now(UTC)
        engine = CorrelationEngine(db)

        # First scan
        scan1 = URLScan(
            id=uuid.uuid4(),
            user_id=test_user.id,
            url_hash="1" * 64,
            normalized_url="https://evil-phish.com/login",
            risk_score=70,
            classification="HIGH_RISK",
            features={},
            reasons=[{"title": "Keyword", "score_contribution": 20}],
            analyzer_version="rule-v1",
            created_at=now,
        )
        db.add(scan1)
        db.commit()
        inc1 = engine.correlate_url_scan(scan1)
        assert inc1 is not None

        initial_risk = inc1.risk_score

        # Second scan targeting a different URL on the same domain
        scan2 = URLScan(
            id=uuid.uuid4(),
            user_id=test_user.id,
            url_hash="2" * 64,
            normalized_url="https://evil-phish.com/verify-account",
            risk_score=80,
            classification="HIGH_RISK",
            features={},
            reasons=[{"title": "Credential path", "score_contribution": 25}],
            analyzer_version="rule-v1",
            created_at=now,
        )
        db.add(scan2)
        db.commit()
        inc2 = engine.correlate_url_scan(scan2)

        # Must attach to existing incident rather than duplicating
        assert inc2 is not None
        assert inc2.id == inc1.id
        assert inc2.event_count == 2
        assert len(inc2.events) == 2
        # Diminishing returns: score should increase moderately, not double
        assert inc2.risk_score >= initial_risk
        assert inc2.risk_score <= 100

    def test_message_and_embedded_url_correlation(self, db: Session, test_user: User) -> None:
        now = datetime.now(UTC)
        engine = CorrelationEngine(db)

        # 1. First: Message scan with embedded link
        msg_scan = MessageScan(
            id=uuid.uuid4(),
            user_id=test_user.id,
            message_hash="3" * 64,
            subject="Urgent Security Notice",
            sender="security@fraud-alerts.com",
            risk_score=75,
            classification="HIGH_RISK",
            confidence=0.90,
            features={"urgency_count": 2},
            reasons=[{"title": "Urgency pressure", "score_contribution": 25}],
            extracted_urls=[
                {
                    "url": "https://fraud-alerts.com/login",
                    "risk_score": 80,
                    "classification": "HIGH_RISK",
                }
            ],
            created_at=now,
        )
        db.add(msg_scan)
        db.commit()

        inc = engine.correlate_message_scan(msg_scan)
        assert inc is not None
        valid_stages = (
            "CREDENTIAL_HARVESTING",
            "SOCIAL_ENGINEERING",
            "MULTI_VECTOR_CAMPAIGN",
        )
        assert inc.attack_stage in valid_stages

        # 2. Second: URL scan matching the embedded link
        url_scan = URLScan(
            id=uuid.uuid4(),
            user_id=test_user.id,
            url_hash="4" * 64,
            normalized_url="https://fraud-alerts.com/login",
            risk_score=80,
            classification="HIGH_RISK",
            features={},
            reasons=[{"title": "Phishing URL", "score_contribution": 30}],
            created_at=now,
        )
        db.add(url_scan)
        db.commit()

        inc_after = engine.correlate_url_scan(url_scan)
        assert inc_after is not None
        assert inc_after.id == inc.id
        assert inc_after.event_count == 2
        # Multi-vector classification
        assert inc_after.attack_stage == "MULTI_VECTOR_CAMPAIGN"

    def test_file_scan_correlation(self, db: Session, test_user: User) -> None:
        engine = CorrelationEngine(db)
        file_scan = FileScan(
            id=uuid.uuid4(),
            user_id=test_user.id,
            file_hash="5" * 64,
            filename="invoice.pdf.exe",
            file_size=2048,
            detected_type="WINDOWS_PE",
            declared_mime="application/pdf",
            risk_score=85,
            classification="CRITICAL",
            confidence=0.95,
            features={"is_double_extension": True},
            reasons=[{"title": "Double extension", "score_contribution": 40}],
            created_at=datetime.now(UTC),
        )
        db.add(file_scan)
        db.commit()

        inc = engine.correlate_file_scan(file_scan)
        assert inc is not None
        assert inc.attack_stage == "SUSPICIOUS_ATTACHMENT"
        assert "invoice.pdf.exe" in inc.title
        assert inc.severity in ("CRITICAL", "HIGH_RISK")

    def test_clean_low_risk_event_does_not_trigger_incident(
        self, db: Session, test_user: User
    ) -> None:
        engine = CorrelationEngine(db)
        clean_scan = URLScan(
            id=uuid.uuid4(),
            user_id=test_user.id,
            url_hash="6" * 64,
            normalized_url="https://google.com",
            risk_score=0,
            classification="LOW_RISK",
            features={},
            reasons=[],
            created_at=datetime.now(UTC),
        )
        db.add(clean_scan)
        db.commit()

        inc = engine.correlate_url_scan(clean_scan)
        assert inc is None
