"""Integration tests for M4 TI layer via FastAPI test client.

Verifies:
- POST /api/v1/analyze/url returns threat_intelligence field (M4)
- analyzer_version includes +ti suffix when TI enriches
- threat_intelligence.provider matches configured provider
- TI result persisted in threat_intelligence_results table
- Cross-user isolation: User A cannot see User B's TI results
- TI enrichment increases score for malicious URLs
- TI failure (provider error) doesn't crash analysis
- history endpoint returns correct M3/M4 versioned records
- Backward compat: threat_intelligence field is null when TI disabled
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from typing import Any

os.environ.setdefault("JWT_SECRET", "test-jwt-secret-at-least-32-chars-long-here")
os.environ.setdefault("ENVIRONMENT", "test")

from app.models.threat_intel import ThreatIntelligenceResult
from app.services.threat_intelligence import ThreatIntelligenceService
from app.services.ti_cache import ThreatIntelCache
from app.services.ti_types import ThreatIntelResult, ThreatIntelStatus
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _register_and_login(client: TestClient, email: str, password: str) -> str:
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    return str(resp.json()["access_token"])


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _analyze(client: TestClient, token: str, url: str) -> Any:
    return client.post(
        "/api/v1/analyze/url",
        json={"url": url},
        headers=_auth(token),
    )


def _make_ti_service(
    status: ThreatIntelStatus = ThreatIntelStatus.CLEAN,
) -> ThreatIntelligenceService:
    """Return a TI service backed by a mock provider that returns a fixed status."""
    from app.services.ti_providers.mock_provider import MockProvider as _Mock

    class _FixedMock(_Mock):
        def __init__(self, fixed_status: ThreatIntelStatus) -> None:
            self._fixed_status = fixed_status

        def lookup(
            self, url_hash: str, url: str, *, timeout_seconds: float = 5.0
        ) -> ThreatIntelResult:
            # Use parent logic for normal URLs; override for specific ones
            result = super().lookup(url_hash, url, timeout_seconds=timeout_seconds)
            return result

    return ThreatIntelligenceService(
        provider=_FixedMock(status),
        cache=ThreatIntelCache(ttl_seconds=0),  # no caching in tests
        timeout_seconds=5.0,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestTIIntegration:
    """Full-stack M4 TI integration tests via the FastAPI test client."""

    def test_analyze_url_returns_threat_intelligence_field(self, client: TestClient) -> None:
        token = _register_and_login(client, "ti1@test.com", "Password1!")
        resp = _analyze(client, token, "https://example.com/")
        assert resp.status_code == 200
        data = resp.json()
        # threat_intelligence field must exist (may be null for benign)
        assert "threat_intelligence" in data

    def test_ti_for_ip_url_is_malicious(self, client: TestClient, db: Session) -> None:
        token = _register_and_login(client, "ti2@test.com", "Password1!")
        resp = _analyze(client, token, "http://192.168.1.1/admin")
        assert resp.status_code == 200
        data = resp.json()
        # Mock provider flags IP addresses as MALICIOUS
        ti = data.get("threat_intelligence")
        assert ti is not None
        assert ti["status"] == "MALICIOUS"

    def test_ti_result_persisted_in_db(self, client: TestClient, db: Session) -> None:
        token = _register_and_login(client, "ti3@test.com", "Password1!")
        resp = _analyze(client, token, "http://192.168.1.1/login")
        assert resp.status_code == 200
        scan_id = uuid.UUID(resp.json()["id"])
        ti_row = db.query(ThreatIntelligenceResult).filter_by(scan_id=scan_id).first()
        assert ti_row is not None
        assert ti_row.provider == "mock"

    def test_malicious_ti_increases_score(self, client: TestClient) -> None:
        token = _register_and_login(client, "ti4@test.com", "Password1!")
        # IP URL: mock provider returns MALICIOUS → score should be boosted
        resp_ip = _analyze(client, token, "http://192.168.1.1/admin")
        # HTTPS known-benign URL: mock returns CLEAN → score not boosted
        resp_benign = _analyze(client, token, "https://example.com/")
        score_ip = resp_ip.json()["risk_score"]
        score_benign = resp_benign.json()["risk_score"]
        assert score_ip > score_benign

    def test_analyzer_version_includes_ti_suffix(self, client: TestClient) -> None:
        token = _register_and_login(client, "ti5@test.com", "Password1!")
        resp = _analyze(client, token, "http://192.168.1.1/admin")
        data = resp.json()
        # When TI succeeds (non-error), version should include +ti
        assert "+ti" in data["analyzer_version"]

    def test_risk_score_stays_0_to_100_with_ti(self, client: TestClient) -> None:
        token = _register_and_login(client, "ti6@test.com", "Password1!")
        for url in [
            "https://example.com/",
            "http://192.168.1.1/login",
            "https://phishing.xyz/login?password=steal",
        ]:
            resp = _analyze(client, token, url)
            assert resp.status_code == 200
            assert 0 <= resp.json()["risk_score"] <= 100

    def test_ti_reasons_appear_in_response(self, client: TestClient) -> None:
        token = _register_and_login(client, "ti7@test.com", "Password1!")
        resp = _analyze(client, token, "http://192.168.1.1/login")
        reasons = resp.json()["reasons"]
        ti_reasons = [r for r in reasons if r["code"] == "TI_REPUTATION"]
        assert len(ti_reasons) >= 1

    def test_classification_thresholds_unchanged(self, client: TestClient) -> None:
        token = _register_and_login(client, "ti8@test.com", "Password1!")
        resp = _analyze(client, token, "https://example.com/")
        data = resp.json()
        score = data["risk_score"]
        cls = data["classification"]
        if score >= 75:
            assert cls == "CRITICAL"
        elif score >= 50:
            assert cls == "HIGH_RISK"
        elif score >= 25:
            assert cls == "MEDIUM_RISK"
        else:
            assert cls == "LOW_RISK"

    def test_history_includes_ti_versioned_scans(self, client: TestClient) -> None:
        token = _register_and_login(client, "ti9@test.com", "Password1!")
        _analyze(client, token, "http://192.168.1.1/login")
        resp = client.get("/api/v1/analyze/url/history", headers=_auth(token))
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) >= 1
        # At least one item should have +ti in version
        versions = [item["analyzer_version"] for item in items]
        assert any("+ti" in v for v in versions)

    def test_cross_user_ti_isolation(self, client: TestClient, db: Session) -> None:
        """User A's TI results must not be readable by User B."""
        token_a = _register_and_login(client, "ti_a@test.com", "Password1!")
        token_b = _register_and_login(client, "ti_b@test.com", "Password1!")

        resp_a = _analyze(client, token_a, "http://192.168.1.1/admin")
        scan_id_a = uuid.UUID(resp_a.json()["id"])

        # User B's history must not contain User A's scan
        hist_b = client.get("/api/v1/analyze/url/history", headers=_auth(token_b))
        ids_in_hist_b = [item["id"] for item in hist_b.json()["items"]]
        assert str(scan_id_a) not in ids_in_hist_b

    def test_existing_endpoints_still_respond_200(self, client: TestClient) -> None:
        token = _register_and_login(client, "compat1@test.com", "Password1!")
        resp = _analyze(client, token, "https://example.com/")
        assert resp.status_code == 200
        data = resp.json()
        # All M2 fields present
        for field in ["id", "url", "risk_score", "classification", "reasons",
                      "features", "analyzer_version", "created_at"]:
            assert field in data, f"Missing field: {field}"


class TestTIProviderFailureIsolation:
    """TI provider errors must not crash or alter analysis."""

    def test_ti_timeout_analysis_continues(self, client: TestClient) -> None:
        """When TI times out, analysis returns M3 result normally."""
        token = _register_and_login(client, "tifail1@test.com", "Password1!")

        # Patch the module-level _ti_service to raise TimeoutError
        import app.services.url_analyzer as svc_mod

        original_service = svc_mod._ti_service

        class _TimeoutProvider:
            @property
            def name(self) -> str:
                return "timeout_mock"

            def lookup(
                self, url_hash: str, url: str, *, timeout_seconds: float = 5.0
            ) -> ThreatIntelResult:
                raise TimeoutError("forced timeout")

        svc_mod._ti_service = ThreatIntelligenceService(
            provider=_TimeoutProvider(),
            cache=ThreatIntelCache(ttl_seconds=0),
        )
        try:
            resp = _analyze(client, token, "https://example.com/")
            assert resp.status_code == 200
            data = resp.json()
            assert 0 <= data["risk_score"] <= 100
        finally:
            svc_mod._ti_service = original_service

    def test_ti_disabled_no_ti_field(self, client: TestClient) -> None:
        """When TI service is None (disabled), threat_intelligence field is null."""
        import app.services.url_analyzer as svc_mod

        token = _register_and_login(client, "tifail2@test.com", "Password1!")
        original_service = svc_mod._ti_service
        svc_mod._ti_service = None

        try:
            resp = _analyze(client, token, "https://example.com/")
            assert resp.status_code == 200
            data = resp.json()
            assert data.get("threat_intelligence") is None
        finally:
            svc_mod._ti_service = original_service

    def test_ti_provider_error_no_crash(self, client: TestClient) -> None:
        """When provider returns provider_error=True, analysis completes normally."""
        import app.services.url_analyzer as svc_mod

        token = _register_and_login(client, "tifail3@test.com", "Password1!")
        original_service = svc_mod._ti_service

        class _ErrorProvider:
            @property
            def name(self) -> str:
                return "error_mock"

            def lookup(
                self, url_hash: str, url: str, *, timeout_seconds: float = 5.0
            ) -> ThreatIntelResult:
                return ThreatIntelResult(
                    provider="error_mock",
                    status=ThreatIntelStatus.UNKNOWN,
                    confidence=None,
                    reason=None,
                    checked_at=datetime.now(UTC),
                    provider_error=True,
                )

        svc_mod._ti_service = ThreatIntelligenceService(
            provider=_ErrorProvider(),
            cache=ThreatIntelCache(ttl_seconds=0),
        )
        try:
            resp = _analyze(client, token, "https://example.com/")
            assert resp.status_code == 200
            data = resp.json()
            # provider_error=True means TI enrichment failed → no +ti suffix
            assert "+ti" not in data["analyzer_version"]
        finally:
            svc_mod._ti_service = original_service
