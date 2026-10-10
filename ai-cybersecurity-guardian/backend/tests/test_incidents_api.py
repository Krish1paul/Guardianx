"""Tests for Incidents API endpoints — M8.

Verifies:
- GET   /api/v1/incidents                  (listing, pagination, filtering)
- GET   /api/v1/incidents/{incident_id}    (detail)
- PATCH /api/v1/incidents/{incident_id}/status (status transition)
- GET   /api/v1/incidents/{incident_id}/timeline (timeline resolution)
- Tenant isolation (cross-user access rejection)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from app.core.auth import create_access_token
from app.models.incident import Incident, IncidentEvent
from app.models.url_scan import URLScan
from app.models.user import User
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


@pytest.fixture
def test_user(db: Session) -> User:
    """Primary authenticated user fixture."""
    user = User(
        id=uuid.uuid4(),
        email=f"incident_user_{uuid.uuid4().hex[:8]}@example.com",
        password_hash="hashed_pw",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def other_user(db: Session) -> User:
    """Second user fixture for tenant isolation tests."""
    user = User(
        id=uuid.uuid4(),
        email=f"other_user_{uuid.uuid4().hex[:8]}@example.com",
        password_hash="hashed_pw",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def auth_headers(test_user: User) -> dict[str, str]:
    """Valid authorization headers for test_user."""
    token = create_access_token(user_id=test_user.id)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def other_auth_headers(other_user: User) -> dict[str, str]:
    """Valid authorization headers for other_user."""
    token = create_access_token(user_id=other_user.id)
    return {"Authorization": f"Bearer {token}"}



@pytest.fixture
def sample_incident(db: Session, test_user: User) -> Incident:
    """Create a sample incident with an attached event."""
    scan = URLScan(
        id=uuid.uuid4(),
        user_id=test_user.id,
        url_hash="9" * 64,
        normalized_url="https://bank-portal-phish.net/login",
        risk_score=90,
        classification="CRITICAL",
        features={},
        reasons=[{"title": "Punycode domain", "score_contribution": 30}],
        analyzer_version="rule-v1",
        created_at=datetime.now(UTC),
    )
    db.add(scan)
    db.commit()

    inc = Incident(
        id=uuid.uuid4(),
        user_id=test_user.id,
        title="High-Risk URL Activity on bank-portal-phish.net",
        severity="CRITICAL",
        risk_score=90,
        confidence=0.92,
        status="OPEN",
        attack_stage="MALICIOUS_LINK",
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        event_count=1,
        indicators=[{"type": "DOMAIN", "value": "bank-portal-phish.net"}],
        reasons=[
            {
                "category": "STRUCTURAL_ANOMALY",
                "severity": "CRITICAL",
                "title": "Initial Detection",
                "explanation": "High threat detected.",
                "score_contribution": 90,
            }
        ],
        created_at=datetime.now(UTC),
    )
    db.add(inc)
    db.commit()

    event_link = IncidentEvent(
        id=uuid.uuid4(),
        incident_id=inc.id,
        event_type="url_scan",
        event_id=scan.id,
        relationship_reason="Root trigger event for incident creation",
        created_at=datetime.now(UTC),
    )
    db.add(event_link)
    db.commit()
    db.refresh(inc)
    return inc


class TestIncidentsAPI:
    """Test suite for incidents API endpoints."""

    def test_list_incidents_unauthenticated_returns_401(self, client: TestClient) -> None:
        response = client.get("/api/v1/incidents")
        assert response.status_code == 401

    def test_list_incidents_success(
        self, client: TestClient, auth_headers: dict[str, str], sample_incident: Incident
    ) -> None:
        response = client.get("/api/v1/incidents", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert data["total"] >= 1
        assert any(item["id"] == str(sample_incident.id) for item in data["items"])

    def test_list_incidents_filter_by_status(
        self, client: TestClient, auth_headers: dict[str, str], sample_incident: Incident
    ) -> None:
        res_open = client.get("/api/v1/incidents?status=OPEN", headers=auth_headers)
        assert res_open.status_code == 200
        assert res_open.json()["total"] >= 1

        res_res = client.get("/api/v1/incidents?status=RESOLVED", headers=auth_headers)
        assert res_res.status_code == 200
        assert res_res.json()["total"] == 0

    def test_get_incident_detail_success(
        self, client: TestClient, auth_headers: dict[str, str], sample_incident: Incident
    ) -> None:
        response = client.get(f"/api/v1/incidents/{sample_incident.id}", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(sample_incident.id)
        assert data["severity"] == "CRITICAL"
        assert len(data["indicators"]) >= 1

    def test_tenant_isolation_other_user_cannot_access_incident(
        self, client: TestClient, other_auth_headers: dict[str, str], sample_incident: Incident
    ) -> None:
        # User B accessing User A's incident must return 404 (prevent ID enumeration)
        response = client.get(f"/api/v1/incidents/{sample_incident.id}", headers=other_auth_headers)
        assert response.status_code == 404

    def test_update_incident_status(
        self, client: TestClient, auth_headers: dict[str, str], sample_incident: Incident
    ) -> None:
        payload = {"status": "INVESTIGATING"}
        response = client.patch(
            f"/api/v1/incidents/{sample_incident.id}/status",
            json=payload,
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "INVESTIGATING"

    def test_get_incident_timeline(
        self, client: TestClient, auth_headers: dict[str, str], sample_incident: Incident
    ) -> None:
        response = client.get(
            f"/api/v1/incidents/{sample_incident.id}/timeline",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["incident_id"] == str(sample_incident.id)
        assert len(data["events"]) >= 1
        ev = data["events"][0]
        assert ev["event_type"] == "url_scan"
        assert "bank-portal-phish.net" in (ev["summary"] or "")
        assert ev["risk_score"] == 90
