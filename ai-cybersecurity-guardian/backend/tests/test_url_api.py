"""API integration tests for URL analysis endpoints — M2.

Tests cover:
- Authentication enforcement
- Valid scan requests
- Schema validation
- Scan persistence
- History endpoint
- Pagination
- Cross-user authorization isolation (User A ≠ User B)
- Adversarial inputs
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _register_and_login(client: TestClient, email: str, password: str) -> str:
    """Register a user and return a valid access token."""
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password},
    )
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert resp.status_code == 200, resp.text
    return str(resp.json()["access_token"])


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _analyze(client: TestClient, token: str, url: str) -> Any:
    return client.post(
        "/api/v1/analyze/url",
        json={"url": url},
        headers=_auth_headers(token),
    )


# ---------------------------------------------------------------------------
# Authentication enforcement
# ---------------------------------------------------------------------------


class TestAuthenticationEnforcement:
    def test_unauthenticated_analyze_rejected(self, client: TestClient) -> None:
        resp = client.post("/api/v1/analyze/url", json={"url": "https://example.com/"})
        assert resp.status_code == 401

    def test_unauthenticated_history_rejected(self, client: TestClient) -> None:
        resp = client.get("/api/v1/analyze/url/history")
        assert resp.status_code == 401

    def test_invalid_token_rejected(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/analyze/url",
            json={"url": "https://example.com/"},
            headers={"Authorization": "Bearer this.is.not.valid"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Successful URL analysis
# ---------------------------------------------------------------------------


class TestSuccessfulAnalysis:
    def test_analyze_https_url(self, client: TestClient) -> None:
        token = _register_and_login(client, "user1@test.com", "Password1")
        resp = _analyze(client, token, "https://example.com/")
        assert resp.status_code == 200
        data = resp.json()
        # M3 ML model may score benign URLs slightly above 0 — accept LOW_RISK
        assert 0 <= data["risk_score"] <= 24
        assert data["classification"] == "LOW_RISK"
        assert data["analyzer_version"] in {"rule-v1", "ml-v1", "rule-v1+ti", "ml-v1+ti"}

    def test_analyze_http_url(self, client: TestClient) -> None:
        token = _register_and_login(client, "user2@test.com", "Password1")
        resp = _analyze(client, token, "http://example.com/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_score"] > 0  # HTTP is a risk indicator
        assert data["classification"] in {"LOW_RISK", "MEDIUM_RISK", "HIGH_RISK", "CRITICAL"}

    def test_response_contains_required_fields(self, client: TestClient) -> None:
        token = _register_and_login(client, "user3@test.com", "Password1")
        resp = _analyze(client, token, "https://example.com/login")
        assert resp.status_code == 200
        data = resp.json()
        required = {
            "id", "url", "risk_score", "classification",
            "reasons", "features", "analyzer_version", "created_at",
        }
        assert required.issubset(data.keys())

    def test_risk_score_in_range(self, client: TestClient) -> None:
        token = _register_and_login(client, "user4@test.com", "Password1")
        for url in [
            "https://example.com/",
            "http://192.168.1.1/login",
            "https://xn--pypal-4ve.com/login",
        ]:
            resp = _analyze(client, token, url)
            assert resp.status_code == 200
            score = resp.json()["risk_score"]
            assert 0 <= score <= 100, f"Score {score} out of range for {url}"

    def test_reasons_present_for_risky_url(self, client: TestClient) -> None:
        token = _register_and_login(client, "user5@test.com", "Password1")
        resp = _analyze(client, token, "http://192.168.1.1/login")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["reasons"]) > 0

    def test_reasons_have_required_fields(self, client: TestClient) -> None:
        token = _register_and_login(client, "user6@test.com", "Password1")
        resp = _analyze(client, token, "http://192.168.1.1/login")
        for reason in resp.json()["reasons"]:
            assert "code" in reason
            assert "severity" in reason
            assert "message" in reason

    def test_scan_is_persisted(self, client: TestClient, db: Session) -> None:
        token = _register_and_login(client, "persist@test.com", "Password1")
        resp = _analyze(client, token, "https://example.com/")
        assert resp.status_code == 200
        scan_id = resp.json()["id"]
        # Verify in the DB
        from app.models.url_scan import URLScan
        scan = db.get(URLScan, uuid.UUID(scan_id))
        assert scan is not None
        # M3 ML model may score benign URLs slightly above 0 — accept LOW_RISK range
        assert 0 <= scan.risk_score <= 24

    def test_analyzer_version_is_ml_v1_or_rule_v1(self, client: TestClient) -> None:
        """M3/M4: analyzer_version is ml-v1 (M3) or ml-v1+ti (M4) or rule fallback variants."""
        token = _register_and_login(client, "ver@test.com", "Password1")
        resp = _analyze(client, token, "https://example.com/")
        version = resp.json()["analyzer_version"]
        assert version in {"rule-v1", "ml-v1", "rule-v1+ti", "ml-v1+ti"}


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


class TestInputValidation:
    def test_missing_url_field(self, client: TestClient) -> None:
        token = _register_and_login(client, "val1@test.com", "Password1")
        resp = client.post(
            "/api/v1/analyze/url",
            json={},
            headers=_auth_headers(token),
        )
        assert resp.status_code == 422

    def test_empty_url(self, client: TestClient) -> None:
        token = _register_and_login(client, "val2@test.com", "Password1")
        resp = _analyze(client, token, "")
        assert resp.status_code == 422

    def test_missing_scheme(self, client: TestClient) -> None:
        token = _register_and_login(client, "val3@test.com", "Password1")
        resp = _analyze(client, token, "example.com/login")
        assert resp.status_code == 422

    def test_unsupported_scheme_ftp(self, client: TestClient) -> None:
        token = _register_and_login(client, "val4@test.com", "Password1")
        resp = _analyze(client, token, "ftp://files.example.com/")
        assert resp.status_code == 422

    def test_unsupported_scheme_file(self, client: TestClient) -> None:
        token = _register_and_login(client, "val5@test.com", "Password1")
        resp = _analyze(client, token, "file:///etc/passwd")
        assert resp.status_code == 422

    def test_javascript_scheme_rejected(self, client: TestClient) -> None:
        token = _register_and_login(client, "val6@test.com", "Password1")
        resp = _analyze(client, token, "javascript:alert(1)")
        assert resp.status_code == 422

    def test_oversized_url(self, client: TestClient) -> None:
        token = _register_and_login(client, "val7@test.com", "Password1")
        long_url = "https://example.com/" + "a" * 3000
        resp = _analyze(client, token, long_url)
        assert resp.status_code == 422

    def test_control_character_rejected(self, client: TestClient) -> None:
        token = _register_and_login(client, "val8@test.com", "Password1")
        resp = _analyze(client, token, "https://example.com/pa\x00th")
        assert resp.status_code == 422

    def test_invalid_body_type(self, client: TestClient) -> None:
        token = _register_and_login(client, "val9@test.com", "Password1")
        resp = client.post(
            "/api/v1/analyze/url",
            content=b"not json",
            headers={**_auth_headers(token), "Content-Type": "application/json"},
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Scan history
# ---------------------------------------------------------------------------


class TestScanHistory:
    def test_empty_history(self, client: TestClient) -> None:
        token = _register_and_login(client, "hist1@test.com", "Password1")
        resp = client.get("/api/v1/analyze/url/history", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_history_returns_scans(self, client: TestClient) -> None:
        token = _register_and_login(client, "hist2@test.com", "Password1")
        _analyze(client, token, "https://example.com/")
        _analyze(client, token, "https://other.com/")

        resp = client.get("/api/v1/analyze/url/history", headers=_auth_headers(token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2

    def test_history_newest_first(self, client: TestClient) -> None:
        token = _register_and_login(client, "hist3@test.com", "Password1")
        _analyze(client, token, "https://first.com/")
        _analyze(client, token, "https://second.com/")
        _analyze(client, token, "https://third.com/")

        resp = client.get("/api/v1/analyze/url/history", headers=_auth_headers(token))
        items = resp.json()["items"]
        # Newest first — created_at should be descending
        timestamps = [item["created_at"] for item in items]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_history_pagination_limit(self, client: TestClient) -> None:
        token = _register_and_login(client, "hist4@test.com", "Password1")
        for i in range(5):
            _analyze(client, token, f"https://example{i}.com/")

        resp = client.get(
            "/api/v1/analyze/url/history",
            params={"limit": 2, "offset": 0},
            headers=_auth_headers(token),
        )
        data = resp.json()
        assert data["total"] == 5
        assert len(data["items"]) == 2
        assert data["limit"] == 2

    def test_history_pagination_offset(self, client: TestClient) -> None:
        token = _register_and_login(client, "hist5@test.com", "Password1")
        for i in range(5):
            _analyze(client, token, f"https://paginated{i}.com/")

        page1 = client.get(
            "/api/v1/analyze/url/history",
            params={"limit": 3, "offset": 0},
            headers=_auth_headers(token),
        ).json()
        page2 = client.get(
            "/api/v1/analyze/url/history",
            params={"limit": 3, "offset": 3},
            headers=_auth_headers(token),
        ).json()

        ids_p1 = {item["id"] for item in page1["items"]}
        ids_p2 = {item["id"] for item in page2["items"]}
        assert ids_p1.isdisjoint(ids_p2), "Pages must not overlap"

    def test_history_item_has_required_fields(self, client: TestClient) -> None:
        token = _register_and_login(client, "hist6@test.com", "Password1")
        _analyze(client, token, "https://example.com/")
        resp = client.get("/api/v1/analyze/url/history", headers=_auth_headers(token))
        item = resp.json()["items"][0]
        assert "id" in item
        assert "url" in item
        assert "risk_score" in item
        assert "classification" in item
        assert "analyzer_version" in item
        assert "created_at" in item

    def test_invalid_limit_rejected(self, client: TestClient) -> None:
        token = _register_and_login(client, "hist7@test.com", "Password1")
        resp = client.get(
            "/api/v1/analyze/url/history",
            params={"limit": 0},
            headers=_auth_headers(token),
        )
        assert resp.status_code == 422

    def test_limit_clamped_to_maximum(self, client: TestClient) -> None:
        token = _register_and_login(client, "hist8@test.com", "Password1")
        resp = client.get(
            "/api/v1/analyze/url/history",
            params={"limit": 999},
            headers=_auth_headers(token),
        )
        # FastAPI validates limit <= 100 at the query param level
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Cross-user authorization isolation (MANDATORY)
# ---------------------------------------------------------------------------


class TestCrossUserIsolation:
    def test_user_a_cannot_see_user_b_history(self, client: TestClient) -> None:
        """Core authorization test: User A must never see User B's scans."""
        token_a = _register_and_login(client, "userA@test.com", "Password1")
        token_b = _register_and_login(client, "userB@test.com", "Password1")

        # User A scans a URL
        _analyze(client, token_a, "https://userA-private.com/")

        # User B's history must be empty
        resp_b = client.get("/api/v1/analyze/url/history", headers=_auth_headers(token_b))
        assert resp_b.status_code == 200
        assert resp_b.json()["total"] == 0
        assert resp_b.json()["items"] == []

    def test_user_b_cannot_see_user_a_history(self, client: TestClient) -> None:
        """Inverse isolation check."""
        token_a = _register_and_login(client, "isolA@test.com", "Password1")
        token_b = _register_and_login(client, "isolB@test.com", "Password1")

        # Both users scan
        _analyze(client, token_a, "https://only-a.com/")
        _analyze(client, token_b, "https://only-b.com/")

        resp_a = client.get("/api/v1/analyze/url/history", headers=_auth_headers(token_a))
        resp_b = client.get("/api/v1/analyze/url/history", headers=_auth_headers(token_b))

        ids_a = {item["id"] for item in resp_a.json()["items"]}
        ids_b = {item["id"] for item in resp_b.json()["items"]}

        # No overlap
        assert ids_a.isdisjoint(ids_b), "User A and User B share scan IDs — isolation violated!"

    def test_each_user_sees_only_their_own_count(self, client: TestClient) -> None:
        token_a = _register_and_login(client, "countA@test.com", "Password1")
        token_b = _register_and_login(client, "countB@test.com", "Password1")

        # A scans 3 URLs, B scans 1
        for i in range(3):
            _analyze(client, token_a, f"https://a-url{i}.com/")
        _analyze(client, token_b, "https://b-url.com/")

        resp_a = client.get("/api/v1/analyze/url/history", headers=_auth_headers(token_a))
        resp_b = client.get("/api/v1/analyze/url/history", headers=_auth_headers(token_b))

        assert resp_a.json()["total"] == 3
        assert resp_b.json()["total"] == 1


# ---------------------------------------------------------------------------
# Adversarial inputs in API
# ---------------------------------------------------------------------------


class TestAdversarialAPIInputs:
    def test_ip_url_scanned_successfully(self, client: TestClient) -> None:
        token = _register_and_login(client, "adv1@test.com", "Password1")
        resp = _analyze(client, token, "http://192.168.1.1/login")
        assert resp.status_code == 200
        assert resp.json()["risk_score"] >= 25

    def test_credential_url_scanned_successfully(self, client: TestClient) -> None:
        token = _register_and_login(client, "adv2@test.com", "Password1")
        resp = _analyze(client, token, "http://user:password@example.com/login")
        assert resp.status_code == 200
        assert resp.json()["risk_score"] >= 25

    def test_punycode_url_scanned(self, client: TestClient) -> None:
        token = _register_and_login(client, "adv3@test.com", "Password1")
        resp = _analyze(client, token, "https://xn--n3h.example.com/")
        assert resp.status_code == 200

    def test_deeply_nested_subdomain(self, client: TestClient) -> None:
        token = _register_and_login(client, "adv4@test.com", "Password1")
        resp = _analyze(client, token, "https://login.verify.account.example.com/")
        assert resp.status_code == 200
        assert resp.json()["risk_score"] > 0

    def test_double_encoded_url(self, client: TestClient) -> None:
        token = _register_and_login(client, "adv5@test.com", "Password1")
        resp = _analyze(client, token, "https://example.com/%2525252525")
        assert resp.status_code == 200

    def test_very_long_but_valid_url(self, client: TestClient) -> None:
        token = _register_and_login(client, "adv6@test.com", "Password1")
        # Just under the limit
        url = "https://example.com/" + "a" * 2000
        resp = _analyze(client, token, url)
        assert resp.status_code == 200
        # Score must be in valid range (ML model may or may not flag length alone)
        assert 0 <= resp.json()["risk_score"] <= 100
