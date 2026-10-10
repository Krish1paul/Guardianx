"""Tests for the GET /health endpoint."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_returns_200(client: TestClient) -> None:
    """GET /health must return HTTP 200."""
    response = client.get("/health")
    assert response.status_code == 200


def test_health_response_body(client: TestClient) -> None:
    """GET /health response body must be exactly {\"status\": \"ok\"}."""
    response = client.get("/health")
    assert response.json() == {"status": "ok"}


def test_health_via_api_prefix_returns_200(client: TestClient) -> None:
    """GET /api/v1/health (prefixed route) must also return HTTP 200."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200


def test_health_content_type_is_json(client: TestClient) -> None:
    """Response Content-Type must be application/json."""
    response = client.get("/health")
    assert "application/json" in response.headers.get("content-type", "")
