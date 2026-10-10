"""Unit & Integration tests for Message / Phishing Analyzer — M7."""

from __future__ import annotations

import uuid

from app.core.security import hash_password
from app.models.message_scan import MessageScan
from app.models.user import User
from app.schemas.unified_analysis import MessageScanRequest
from app.schemas.url_analysis import RiskClassification
from app.services.analyzers.message_analyzer import MessageAnalyzer
from ml.features.message_features import extract_message_features
from sqlalchemy.orm import Session


def _make_user(db: Session, email: str = "test@example.com") -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password("S3cur3P@ssw0rd!"),
    )
    db.add(user)
    db.flush()
    return user


class TestMessageFeatureExtraction:
    def test_phishing_features_detected(self) -> None:
        text = (
            "URGENT: Your account has been suspended! Please verify your password immediately "
            "within 24 hours at http://evil-login.fake/verify to restore access. "
            "Click here to confirm your identity."
        )
        features = extract_message_features(
            text, subject="Urgent Notice", sender="support@security-bank.fake"
        )
        assert features.urgency_count > 0
        assert features.credential_count > 0
        assert features.suspension_count > 0
        assert features.call_to_action_count > 0
        assert len(features.extracted_urls) == 1
        assert features.extracted_urls[0] == "http://evil-login.fake/verify"

    def test_benign_message_features(self) -> None:
        text = (
            "Hi team, sprint planning meeting is at 10 AM tomorrow in Conference Room B. "
            "Please review the agenda beforehand."
        )
        features = extract_message_features(
            text, subject="Meeting Notes", sender="alice@company.internal"
        )
        assert features.urgency_count == 0
        assert features.credential_count == 0
        assert features.suspension_count == 0
        assert features.financial_count == 0
        assert len(features.extracted_urls) == 0

    def test_multiple_url_extraction(self) -> None:
        text = "Check these links: https://example.com/one and https://test.org/two?query=val"
        features = extract_message_features(text)
        assert len(features.extracted_urls) == 2
        assert "https://example.com/one" in features.extracted_urls
        assert "https://test.org/two?query=val" in features.extracted_urls


class TestMessageAnalyzerService:
    def test_analyze_phishing_message(self, db: Session) -> None:
        user = _make_user(db, "phish_user@example.com")
        analyzer = MessageAnalyzer(db)
        req = MessageScanRequest(
            message=(
                "CRITICAL ALERT: Your PayPal account has been locked due to unauthorized charges "
                "of $950.00. You must verify your credentials immediately within 24 hours at "
                "http://fake-paypal-verify.com/login or your funds will be frozen."
            ),
            subject="Account Locked - Unauthorized Charge",
            sender="security@paypal-notice.com",
        )
        res = analyzer.analyze(req, user_id=user.id)

        assert res.risk_score >= 60
        assert res.classification in {RiskClassification.HIGH_RISK, RiskClassification.CRITICAL}
        assert res.confidence >= 0.70
        assert len(res.reasons) >= 2
        assert any(r.title == "Credential Harvesting Attempt" for r in res.reasons)
        assert any(r.title == "Urgency Pressure & Suspension Threats" for r in res.reasons)

        # Privacy check: Verify DB record exists but raw body is NOT stored
        db_record = db.get(MessageScan, res.id)
        assert db_record is not None
        assert db_record.user_id == user.id
        assert db_record.message_hash == res.message_hash
        assert not hasattr(db_record, "raw_message")
        assert not hasattr(db_record, "body")

    def test_analyze_benign_message(self, db: Session) -> None:
        user = _make_user(db, "benign_user@example.com")
        analyzer = MessageAnalyzer(db)
        req = MessageScanRequest(
            message="Hi Bob, let's catch up on Friday over lunch at 12:30 PM. Let me know!",
            subject="Lunch on Friday",
        )
        res = analyzer.analyze(req, user_id=user.id)

        assert res.risk_score < 30
        assert res.classification == RiskClassification.LOW_RISK

    def test_message_tenant_isolation(self, db: Session) -> None:
        user1 = _make_user(db, "user1@example.com")
        user2 = _make_user(db, "user2@example.com")

        analyzer = MessageAnalyzer(db)
        req1 = MessageScanRequest(message="User 1 secret message")
        res1 = analyzer.analyze(req1, user_id=user1.id)

        req2 = MessageScanRequest(message="User 2 secret message")
        res2 = analyzer.analyze(req2, user_id=user2.id)

        # User 1 should only find their own scan
        user1_scans = (
            db.query(MessageScan)
            .filter(MessageScan.user_id == user1.id)
            .all()
        )
        assert len(user1_scans) == 1
        assert user1_scans[0].id == res1.id

        user2_scans = (
            db.query(MessageScan)
            .filter(MessageScan.user_id == user2.id)
            .all()
        )
        assert len(user2_scans) == 1
        assert user2_scans[0].id == res2.id
