"""Integration tests for multi-vector API routes and security boundaries — M7."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _register_and_login(client: TestClient, email: str, password: str = "P@ssw0rd123!") -> str:
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


class TestMessageAPI:
    def test_analyze_message_unauthenticated_returns_401(self, client: TestClient) -> None:
        resp = client.post("/api/v1/analyze/message", json={"message": "test"})
        assert resp.status_code == 401

    def test_analyze_message_authenticated_success(self, client: TestClient) -> None:
        token = _register_and_login(client, "msg_user@example.com")
        payload = {
            "message": "Urgent notice: Account suspension imminent. Verify your password at http://fake.com/login",
            "subject": "Action Required",
            "sender": "support@bank-security.fake",
        }
        resp = client.post(
            "/api/v1/analyze/message",
            json=payload,
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()

        assert "id" in data
        assert "message_hash" in data
        assert "risk_score" in data
        assert "classification" in data
        assert "confidence" in data
        assert "reasons" in data
        assert isinstance(data["reasons"], list)
        assert len(data["reasons"]) > 0

    def test_analyze_message_empty_body_rejected(self, client: TestClient) -> None:
        token = _register_and_login(client, "empty_msg_user@example.com")
        resp = client.post(
            "/api/v1/analyze/message",
            json={"message": "   "},
            headers=_auth_headers(token),
        )
        assert resp.status_code == 422

    def test_message_history_pagination(self, client: TestClient) -> None:
        token = _register_and_login(client, "history_msg_user@example.com")
        # Submit 2 scans
        client.post(
            "/api/v1/analyze/message",
            json={"message": "First message"},
            headers=_auth_headers(token),
        )
        client.post(
            "/api/v1/analyze/message",
            json={"message": "Second message"},
            headers=_auth_headers(token),
        )

        resp = client.get(
            "/api/v1/analyze/message/history?limit=10&offset=0",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 2
        assert len(data["items"]) >= 2
        assert "message_hash" in data["items"][0]


class TestFileAPI:
    def test_analyze_file_unauthenticated_returns_401(self, client: TestClient) -> None:
        files = {"file": ("test.txt", b"plain text", "text/plain")}
        resp = client.post("/api/v1/analyze/file", files=files)
        assert resp.status_code == 401

    def test_analyze_file_authenticated_success(self, client: TestClient) -> None:
        token = _register_and_login(client, "file_api_user@example.com")
        files = {"file": ("notes.txt", b"Benign text data for static inspection.", "text/plain")}
        resp = client.post(
            "/api/v1/analyze/file",
            files=files,
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()

        assert "id" in data
        assert "file_hash" in data
        assert data["filename"] == "notes.txt"
        assert data["risk_score"] < 30
        assert data["classification"] == "LOW_RISK"
        assert data["detected_type"] == "PLAIN_TEXT"

    def test_analyze_file_double_extension_flagged(self, client: TestClient) -> None:
        token = _register_and_login(client, "double_ext_user@example.com")
        files = {"file": ("report.pdf.exe", b"MZ" + b"\x00" * 80, "application/octet-stream")}
        resp = client.post(
            "/api/v1/analyze/file",
            files=files,
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()

        assert data["risk_score"] >= 60
        assert data["classification"] in {"HIGH_RISK", "CRITICAL"}
        assert any("Double File Extension" in r["title"] for r in data["reasons"])

    def test_file_history_pagination(self, client: TestClient) -> None:
        token = _register_and_login(client, "file_hist_user@example.com")
        files = {"file": ("test1.txt", b"content1", "text/plain")}
        client.post(
            "/api/v1/analyze/file",
            files=files,
            headers=_auth_headers(token),
        )

        resp = client.get(
            "/api/v1/analyze/file/history?limit=5&offset=0",
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert len(data["items"]) >= 1


class TestUnifiedAPI:
    def test_unified_url_analysis(self, client: TestClient) -> None:
        token = _register_and_login(client, "unified_url_user@example.com")
        resp = client.post(
            "/api/v1/analyze",
            json={"type": "url", "url": "https://example.com/login"},
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "url" in data
        assert "risk_score" in data

    def test_unified_message_analysis(self, client: TestClient) -> None:
        token = _register_and_login(client, "unified_msg_user@example.com")
        resp = client.post(
            "/api/v1/analyze",
            json={"type": "message", "message": "Urgent: verify your account now."},
            headers=_auth_headers(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "message_hash" in data
        assert "risk_score" in data

    def test_unified_missing_fields_rejected(self, client: TestClient) -> None:
        token = _register_and_login(client, "unified_err_user@example.com")
        resp = client.post(
            "/api/v1/analyze",
            json={"type": "url"},
            headers=_auth_headers(token),
        )
        assert resp.status_code == 422

        resp2 = client.post(
            "/api/v1/analyze",
            json={"type": "message"},
            headers=_auth_headers(token),
        )
        assert resp2.status_code == 422
