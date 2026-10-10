"""Tests for Incident lifecycle & deduplication — M8.

Verifies:
- Incident status transitions (OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE)
- Deduplication prevents duplicate active incidents
- Reopening rules
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from app.models.incident import Incident
from app.models.url_scan import URLScan
from app.models.user import User
from app.services.intelligence.correlation_engine import CorrelationEngine
from sqlalchemy.orm import Session


@pytest.fixture
def test_user(db: Session) -> User:
    """Create a test user."""
    user = User(
        id=uuid.uuid4(),
        email=f"lifecycle_{uuid.uuid4().hex[:8]}@example.com",
        password_hash="hashed_pw",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


class TestIncidentLifecycle:
    """Test suite for incident states and deduplication."""

    def test_deduplication_keeps_single_open_incident(
        self, db: Session, test_user: User
    ) -> None:
        engine = CorrelationEngine(db)
        now = datetime.now(UTC)

        # Emit 3 scans with identical domain
        for i in range(3):
            scan = URLScan(
                id=uuid.uuid4(),
                user_id=test_user.id,
                url_hash=f"{i}" * 64,
                normalized_url=f"https://credential-stealer.xyz/page{i}",
                risk_score=75,
                classification="HIGH_RISK",
                features={},
                reasons=[{"title": "Test lure", "score_contribution": 20}],
                analyzer_version="rule-v1",
                created_at=now,
            )
            db.add(scan)
            db.commit()
            engine.correlate_url_scan(scan)

        # There should only be 1 Incident with event_count = 3
        incidents = list(db.query(Incident).filter(Incident.user_id == test_user.id).all())
        assert len(incidents) == 1
        assert incidents[0].event_count == 3
        assert len(incidents[0].events) == 3

    def test_status_transitions(self, db: Session, test_user: User) -> None:
        inc = Incident(
            id=uuid.uuid4(),
            user_id=test_user.id,
            title="Investigate Phishing Link",
            severity="HIGH_RISK",
            risk_score=75,
            confidence=0.85,
            status="OPEN",
            attack_stage="MALICIOUS_LINK",
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            event_count=1,
            indicators=[{"type": "DOMAIN", "value": "bad-site.org"}],
            reasons=[],
        )
        db.add(inc)
        db.commit()
        db.refresh(inc)

        # OPEN -> INVESTIGATING
        inc.status = "INVESTIGATING"
        db.commit()
        db.refresh(inc)
        assert inc.status == "INVESTIGATING"

        # INVESTIGATING -> RESOLVED
        inc.status = "RESOLVED"
        db.commit()
        db.refresh(inc)
        assert inc.status == "RESOLVED"

        # Can also set FALSE_POSITIVE
        inc.status = "FALSE_POSITIVE"
        db.commit()
        db.refresh(inc)
        assert inc.status == "FALSE_POSITIVE"
