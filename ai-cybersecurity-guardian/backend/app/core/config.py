"""Application configuration.

Settings are loaded from environment variables (and a local .env file in
development). No secret ever has a real default value here -- production
deployments must fail fast if a required secret is missing.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    environment: str = Field(default="development")

    database_url: str = Field(
        default="postgresql+psycopg://postgres:postgres@localhost:5432/cyberguardian",
    )

    jwt_secret: str = Field(default="")
    jwt_algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=15)
    refresh_token_expire_days: int = Field(default=7)

    cors_origins: str = Field(default="http://localhost:5173")

    # ---- Rate limiting (M1 in-memory / M5 Redis-backed) ----
    # Requests per 60-second window, per source IP, per endpoint.
    rate_limit_login: int = Field(default=10)
    rate_limit_register: int = Field(default=5)
    rate_limit_refresh: int = Field(default=20)

    # ---- Redis configuration (M5) ----
    redis_url: str = Field(default="redis://localhost:6379/0")
    redis_enabled: bool = Field(default=False)
    redis_socket_timeout: float = Field(default=2.0)

    # ---- Database Connection Pool (M5) ----
    db_pool_size: int = Field(default=5)
    db_max_overflow: int = Field(default=10)
    db_pool_timeout: float = Field(default=30.0)
    db_pool_recycle: int = Field(default=1800)
    db_pool_pre_ping: bool = Field(default=True)

    # ---- Security & Hardening (M5) ----
    max_request_body_bytes: int = Field(default=1_048_576)  # 1 MB
    allowed_hosts: str = Field(default="*")  # Comma-separated list of trusted hosts

    # ---- Threat Intelligence (M4) ----
    # Kill-switch: set to false to disable TI enrichment entirely.
    threat_intel_enabled: bool = Field(default=True)

    # VirusTotal v3 API key.  Empty string (the default) → mock provider is used.
    # Never commit or log this value.
    virustotal_api_key: str = Field(default="")

    # Hard network timeout for any external TI provider call (seconds).
    threat_intel_timeout_seconds: float = Field(default=5.0)

    # How long (seconds) to keep a TI result in the in-memory cache.
    # Default 1 hour.  Set to 0 to disable caching.
    threat_intel_cache_ttl_seconds: int = Field(default=3600)

    # Maximum score points that TI enrichment may add to the ML baseline.
    # The final score is always clamped to [0, 100].
    threat_intel_max_boost: int = Field(default=30)

    @field_validator("environment")
    @classmethod
    def _validate_environment(cls, value: str) -> str:
        allowed = {"development", "test", "staging", "production"}
        if value not in allowed:
            raise ValueError(f"environment must be one of {allowed}, got {value!r}")
        return value

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def allowed_hosts_list(self) -> list[str]:
        return [host.strip() for host in self.allowed_hosts.split(",") if host.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def validate_production_secrets(self) -> None:
        if not self.is_production:
            return
        missing: list[str] = []
        if not self.jwt_secret or len(self.jwt_secret) < 32:
            missing.append("JWT_SECRET (must be set and at least 32 characters)")
        if "postgres:postgres@localhost" in self.database_url:
            missing.append("DATABASE_URL (must not use default local credentials)")
        if "*" in self.cors_origins_list:
            missing.append("CORS_ORIGINS (wildcard '*' is forbidden in production)")
        if missing:
            raise RuntimeError(
                "Refusing to start in production with missing/insecure configuration: "
                + ", ".join(missing)
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
