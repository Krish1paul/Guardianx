"""Tests for M5 Health Endpoints, DB Connection Pool, and Infrastructure Configuration."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from app.api.deps import get_db
from app.core import config
from app.core.redis import get_redis_client
from app.db.session import create_db_engine
from app.main import app
from fastapi.testclient import TestClient


class TestHealthEndpoints:
    def test_health_baseline(self, client: TestClient) -> None:
        res = client.get("/health")
        assert res.status_code == 200
        assert res.json() == {"status": "ok"}

    def test_liveness_endpoints(self, client: TestClient) -> None:
        res1 = client.get("/health/live")
        assert res1.status_code == 200
        assert res1.json() == {"status": "alive"}

        res2 = client.get("/api/v1/health/live")
        assert res2.status_code == 200
        assert res2.json() == {"status": "alive"}

    def test_readiness_healthy(self, client: TestClient) -> None:
        res = client.get("/health/ready")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ready"
        assert data["database"] == "healthy"
        assert data["redis"] in {"healthy", "disabled"}

    def test_readiness_db_failure(self, client: TestClient) -> None:
        def _failing_db() -> Generator[Any, None, None]:
            mock_session = MagicMock()
            mock_session.execute.side_effect = Exception("DB Connection Lost")
            yield mock_session

        app.dependency_overrides[get_db] = _failing_db
        try:
            res = client.get("/health/ready")
            assert res.status_code == 503
            data = res.json()
            assert data["status"] == "unhealthy"
            assert data["database"] == "unhealthy"
            # Ensure no stack trace or internal connection string leaked
            assert "DB Connection Lost" not in res.text
        finally:
            app.dependency_overrides.pop(get_db, None)

    def test_readiness_redis_failure(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_redis = MagicMock()
        mock_redis.ping.return_value = False

        monkeypatch.setenv("REDIS_ENABLED", "true")
        config.get_settings.cache_clear()

        app.dependency_overrides[get_redis_client] = lambda: mock_redis
        try:
            res = client.get("/health/ready")
            assert res.status_code == 503
            assert res.json()["status"] == "unhealthy"
            assert res.json()["redis"] == "unhealthy"
        finally:
            app.dependency_overrides.pop(get_redis_client, None)
            config.get_settings.cache_clear()


class TestDatabasePoolConfig:
    def test_sqlite_engine_creation(self) -> None:
        engine = create_db_engine("sqlite:///:memory:")
        assert engine.url.drivername == "sqlite"

    def test_postgres_pool_settings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DB_POOL_SIZE", "15")
        monkeypatch.setenv("DB_MAX_OVERFLOW", "20")
        monkeypatch.setenv("DB_POOL_TIMEOUT", "45")

        config.get_settings.cache_clear()

        engine = create_db_engine("postgresql+psycopg://user:pass@localhost:5432/test")
        pool = getattr(engine, "pool", None)
        assert pool is not None
        assert pool.size() == 15
        config.get_settings.cache_clear()


class TestInfrastructureFiles:
    def test_dockerfile_hardening(self) -> None:
        dockerfile_path = Path(__file__).parents[1] / "Dockerfile"
        assert dockerfile_path.exists()
        content = dockerfile_path.read_text(encoding="utf-8")
        assert "USER appuser" in content
        assert "HEALTHCHECK" in content
        assert "python:3.11-slim" in content

    def test_docker_compose_redis(self) -> None:
        compose_path = Path(__file__).parents[2] / "docker-compose.yml"
        assert compose_path.exists()
        content = compose_path.read_text(encoding="utf-8")
        assert "redis:" in content
        assert "redis:7-alpine" in content
        assert "REDIS_URL" in content

    def test_ci_workflow_content(self) -> None:
        ci_path = Path(__file__).parents[2] / ".github" / "workflows" / "ci.yml"
        assert ci_path.exists()
        content = ci_path.read_text(encoding="utf-8")
        assert "ruff check" in content
        assert "mypy" in content
        assert "pytest" in content
        assert "alembic check" in content
