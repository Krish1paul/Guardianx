# Development Roadmap — AI Personal Cybersecurity Guardian

> This roadmap reflects the current project plan. Only items marked ✅ are implemented and verifiable in the codebase.

---

## M0 — Foundation ✅ COMPLETE

**Goal**: Establish the project skeleton, data models, and development toolchain.

### Delivered

- [x] Project directory structure (`backend/`, `frontend/`, `ml/`, `docs/`, etc.)
- [x] FastAPI application factory with `GET /health` endpoint
- [x] Security headers middleware (X-Content-Type-Options, X-Frame-Options, Referrer-Policy)
- [x] CORS middleware with environment-driven origin allow-list
- [x] PostgreSQL schema — `users` and `audit_logs` tables
- [x] SQLAlchemy 2.x ORM models (UUID PKs, indexes, FK relationship, bidirectional `relationship()`)
- [x] Alembic migrations — initial schema (`0001_initial_schema`)
- [x] `pydantic-settings` configuration — all secrets from environment variables
- [x] Production startup guard — rejects missing/weak JWT secret
- [x] Structured logging with sensitive-field redaction filter
- [x] bcrypt password hashing utilities (no auth routes yet)
- [x] Docker Compose — PostgreSQL (health check, persistent volume) + backend service
- [x] pytest test suite — health endpoint, DB connectivity, User model, AuditLog relationship
- [x] `ruff` linting — zero violations
- [x] `mypy --strict` — zero violations

---

## M1 — Authentication ✅ COMPLETE

**Goal**: Secure user authentication and session management.

### Delivered

- [x] `POST /api/v1/auth/register` — user registration with email + bcrypt password
- [x] `POST /api/v1/auth/login` — returns signed JWT access + refresh token pair
- [x] `POST /api/v1/auth/refresh` — rotates refresh token (with family revocation on reuse)
- [x] `POST /api/v1/auth/logout` — revokes refresh token
- [x] `GET /api/v1/auth/me` — returns authenticated user profile
- [x] JWT Bearer token authentication via `get_current_user` dependency
- [x] Rate limiting on auth endpoints (brute-force protection)
- [x] Refresh token rotation with token family revocation on reuse detection
- [x] Audit log entries for login, logout, failed attempts
- [x] `refresh_tokens` database table (Alembic migration `0002`)

---

## M2 — URL Threat Analyzer ✅ COMPLETE

**Goal**: Deterministic, stateless, explainable URL analysis pipeline.

### Delivered

- [x] `POST /api/v1/analyze/url` — authenticated URL threat analysis
- [x] `GET /api/v1/analyze/url/history` — paginated scan history
- [x] URL validation (scheme allowlist, length cap, control char rejection)
- [x] URL normalization (canonical form for consistent hashing)
- [x] SHA-256 URL hashing (stable, not Python's `hash()`)
- [x] Pure stateless feature extraction (`ml/features/url_features.py`)
  - Structural, host/domain, security, and lexical features
- [x] Deterministic weighted rule engine (`ml/features/url_risk_engine.py`)
  - Combination-aware rules (keyword + IP, keyword + HTTP, etc.)
  - Clamped score 0–100 with four classification tiers
- [x] Explainable structured reasons with `code`, `severity`, `message`
- [x] M3-ready inference shim (`ml/inference/url_inference.py`) — single swap point
- [x] `url_scans` database table (Alembic migration `0003`)
- [x] SSRF-safe by design: no network requests to submitted URLs
- [x] Cross-user scan isolation enforced at DB query level
- [x] Analyzer versioning (`rule-v1` persisted with each scan)
- [x] Privacy-documented URL storage decision
- [x] Comprehensive test suite (validation, features, risk engine, API, SSRF safety)
- [x] `ruff` — zero violations
- [x] `mypy --strict` — zero violations
- [x] Documentation updated (architecture, database, threat-model, roadmap)

### M2 Limitations (documented)

> M2 is a deterministic heuristic analyzer and is NOT a complete phishing/malware detection system.

- Does not fetch or verify URLs
- Does not check reputation databases
- Combination rules minimize but do not eliminate false positives
- M3 will add a trained ML classifier

---

## M3 — ML Pipeline ✅ COMPLETE

**Goal**: On-device ML classifier for phishing URL detection, replacing M2 rule engine.

### Delivered

- [x] Stable 28-feature numeric schema (`ml/features/url_feature_vector.py`)
  - Deterministic `features_to_vector()` shared by training and inference
  - `FEATURE_SCHEMA_VERSION` validated at inference load time
- [x] Dataset loader with validation, deduplication, conflict detection, stratified split (`ml/preprocessing/url_dataset.py`)
- [x] Training pipeline (`ml/training/train_url_model.py`)
  - Evaluates Logistic Regression and Random Forest (XGBoost if installed)
  - Selects by recall (security: minimize false negatives), tie-broken by F1
  - Fixed random seed (42), deterministic train/val/test split
- [x] Evaluation harness (`ml/evaluation/evaluate.py`)
  - Precision, recall, F1, ROC-AUC, FPR, FNR, confusion matrix
  - Threshold search minimizing FNR subject to min-precision constraint
  - Markdown evaluation report (`ml/evaluation/reports/url_model_v1.md`)
- [x] ML inference swap (`ml/inference/url_inference.py`)
  - `analyzer_version="ml-v1"` replaces rule-v1
  - **Fallback** to rule-v1 if artifact missing/corrupt/schema mismatch (never mislabels)
  - Trusted model path enforced via `os.path.realpath()` check
- [x] Explainability (`ml/inference/url_explainer.py`)
  - Feature importances → `list[RiskReason]` using existing `ReasonCode`/`Severity` enums
  - No SHAP dependency; supports RF (`feature_importances_`) and LR (abs coefficients)
- [x] Versioned model artifacts (`ml/models/url_model_v1/`)
  - `model.pkl`, `metadata.json`, `feature_schema.json`
  - Artifacts are gitignored — not committed to version control
- [x] Synthetic fixture for pipeline testing (`ml/datasets/fixtures/sample_urls.csv`)
  - Clearly labelled as non-production in metadata and logs
- [x] Comprehensive M3 test suite (138 new tests):
  - `test_url_feature_vector.py` — stable schema contracts
  - `test_url_dataset.py` — loading, validation, deduplication, splits
  - `test_url_training.py` — artifact existence, metadata keys, model loadability
  - `test_url_evaluation.py` — metrics range, confusion matrix, threshold search
  - `test_url_inference_ml.py` — ML scoring, fallback behaviour, determinism
  - `test_url_explainability.py` — reason codes, severity, deduplication
  - `test_url_model_security.py` — SSRF, subprocess, trusted path, corrupt model
- [x] No API changes — existing `url_scans` contract preserved; historical `rule-v1` scans untouched
- [x] `ruff` — zero violations
- [x] `mypy --strict` — zero violations
- [x] Full test suite: **424 passed, 0 failed**
- [x] Documentation: `docs/ml-pipeline.md` created; `docs/architecture.md` updated

---

## M4 — Threat Intelligence & URL Reputation ✅ COMPLETE

**Goal**: Enrich ML-scored URLs with external reputation signals.

### Delivered

- [x] `ThreatIntelligenceProvider` protocol (`app/services/threat_intelligence.py`)
  - Structural typing — new providers only need to implement `.lookup()`
  - Userinfo stripped from URL before any provider call (credential safety)
- [x] `MockProvider` (`app/services/ti_providers/mock_provider.py`)
  - Zero network calls — used in development, tests, and when no API key is configured
  - Deterministic: IPv4 host → MALICIOUS, suspicious TLD → SUSPICIOUS, benign hosts → CLEAN
- [x] `VirusTotalProvider` (`app/services/ti_providers/virustotal_provider.py`)
  - VirusTotal v3 URL lookup with ratio-based MALICIOUS/SUSPICIOUS/CLEAN classification
  - All failure modes isolated: timeout, HTTP 4xx/5xx, malformed JSON, missing key → provider_error=True
  - API key never logged, never in any response field
- [x] `ThreatIntelligenceService` orchestrator
  - In-memory LRU cache (`ThreatIntelCache`) keyed by SHA-256 hash
  - TTL configurable via `THREAT_INTEL_CACHE_TTL_SECONDS` (default 3600s)
  - Kill-switch: `THREAT_INTEL_ENABLED=false` disables TI entirely
- [x] `score_blender.blend()` — additive-only score blending
  - MALICIOUS → +up to 30 points (configurable)
  - SUSPICIOUS → +up to 15 points
  - CLEAN/UNKNOWN/error → +0 (TI cannot reduce ML baseline)
  - Final score always clamped to [0, 100]
- [x] `ThreatIntelligenceResult` ORM model and `threat_intelligence_results` DB table
  - Separate table — `url_scans` rows are never modified
  - FK → `url_scans.id` with CASCADE on delete
  - Migration: `alembic/versions/0004_add_threat_intelligence.py`
- [x] `URLScanResponse.threat_intelligence` optional field — fully backward-compatible
- [x] `analyzer_version` extended: `ml-v1+ti` when TI succeeds, unchanged on error
- [x] New reason code `TI_REPUTATION` in `ReasonCode` enum
- [x] `VIRUSTOTAL_API_KEY`, `THREAT_INTEL_*` settings added to `Settings`
- [x] `virustotal_api_key` added to log redaction filter
- [x] M4 test suite (134 new tests):
  - `test_ti_provider_interface.py` — protocol compliance, mock determinism, no-network guarantee
  - `test_ti_score_blender.py` — blending math, edge cases, boundary conditions
  - `test_ti_cache.py` — TTL expiry, max-size eviction, thread safety
  - `test_ti_virustotal.py` — mocked HTTP success/failure, response parsing, key security
  - `test_ti_integration.py` — full API flow, DB persistence, cross-user isolation, failure isolation
  - `test_ti_security.py` — API key not leaked, URL sanitization, no network from mock, score bounds
- [x] `docs/threat-intelligence.md` created
- [x] `docs/architecture.md` updated
- [x] `ruff` — zero violations
- [x] `mypy --strict` — zero violations
- [x] Full test suite: **558 passed, 0 failed**

### M3 Limitations (documented)

> The model is trained on a synthetic fixture. Replace with a real labeled dataset before production deployment.

- URL signals only (no page content, no reputation database)
- Logistic Regression on synthetic data — limited generalization
- See `docs/ml-pipeline.md` for full limitations

---

## M5 — Production Hardening ✅ COMPLETE

**Goal**: Security hardening, resilience, operational observability, and deployment readiness.

### Delivered

- [x] Pluggable Redis abstraction (`app/core/redis.py`)
  - `RedisClientProtocol` with structural typing
  - Thread-safe `InMemoryRedisClient` for dev/test and automatic fallback
  - `RedisClient` wrapper with connection pooling & timeout guards
- [x] Redis-backed sliding-window rate limiting (`app/core/rate_limit.py`)
  - Sliding window logs using Redis sorted sets (ZSET)
  - `FallbackRateLimiter` ensures auth and scan endpoints never crash if Redis is offline
- [x] Access-Token JTI Revocation (`app/services/token_revocation.py`)
  - Blocklist keyed by `revoked_jti:{jti}` with TTL matching token expiry
  - `POST /api/v1/auth/logout` revokes caller's access token immediately
  - `get_current_user` dependency enforces blocklist check across all protected routes (`/auth/me`, `/analyze/url`)
- [x] Security middleware & Request Tracing
  - `CorrelationIdMiddleware` (`X-Request-ID` and `X-Correlation-ID`)
  - `BodySizeLimitMiddleware` (enforces `max_request_body_bytes`, returns HTTP 413)
  - Safe structured logging (`RedactingFormatter` & `RedactSensitiveDataFilter`) redacts sensitive query parameters, bearer tokens, passwords, and API keys
  - Centralized global exception handler returning standard 500 without leaking stack traces or credentials
  - Production configuration validation (`validate_production_secrets()`): enforces strong JWT secret, disallows wildcard CORS and default local DB URLs in production
- [x] Health Probes (`app/api/v1/health.py`)
  - `GET /health` contract preserved for backward compatibility
  - `GET /health/live` & `GET /api/v1/health/live` liveness probes (zero dependencies)
  - `GET /health/ready` & `GET /api/v1/health/ready` readiness probes checking PostgreSQL + Redis
- [x] Database Connection Pooling (`app/db/session.py`)
  - Configurable SQLAlchemy parameters: `db_pool_size`, `db_max_overflow`, `db_pool_timeout`, `db_pool_recycle`, `db_pool_pre_ping`
- [x] Hardened Docker & Compose Setup
  - Multi-stage Dockerfile running as non-root `appuser:appgroup` with explicit `HEALTHCHECK`
  - `docker-compose.yml` updated with Redis 7 Alpine service, persistent volumes, and healthchecks
- [x] GitHub Actions CI Workflow (`.github/workflows/ci.yml`)
  - Runs `ruff`, `mypy --strict`, `pytest --cov=app --cov-fail-under=80`, and `alembic check`
- [x] Comprehensive test suite (46 new tests, 604 total):
  - `test_redis.py` — protocol compliance, in-memory operations, timeout & error handling
  - `test_redis_rate_limit.py` — sliding window logs, window eviction, fallback on Redis failure
  - `test_token_revocation.py` — revocation with TTL, error tolerance
  - `test_m5_security.py` — revoked token rejection at `/me` & `/analyze/url`, correlation ID, redaction, 413 body size limit, production config guards
  - `test_m5_health_pool.py` — liveness/readiness, DB/Redis failure isolation, pool configuration, Docker/CI syntax checks
- [x] Full test suite: **604 passed, 0 failed** (93% statement coverage)
- [x] `ruff` — zero violations
- [x] `mypy --strict` — zero violations

---

## M6 — Security Dashboard & Analytics ✅ COMPLETE

**Goal**: Build a premium, production-quality cybersecurity SOC dashboard.

### Delivered

- [x] React 18 + Vite + TypeScript frontend application
- [x] Dark cybersecurity SOC design system with custom ThreatGauge radial SVG meter
- [x] Overview dashboard with real-time statistics, severity distributions, and scan velocity
- [x] Quick Scan command palette (`Cmd+K` / `Ctrl+K`)
- [x] Modular navigation sections: Monitor (Overview, Security Analytics, Threat Center), Analyze (URL Scanner, Threat Intelligence, Scan History), and System (Reports, Alerts, Settings)
- [x] Authentication flows (login, registration, session persistence, automatic token refresh on 401)

---

## M7 — Advanced Multi-Vector Threat Detection & Explainability ✅ COMPLETE

**Goal**: Transform CyberGuardian into an explainable multi-vector threat engine (URL, Message, File).

### Delivered

- [x] Multi-Vector Extensible Architecture (`BaseAnalyzer` abstraction and normalized results)
- [x] Unified Risk Scoring Engine (`UnifiedRiskEngine`):
  - Anti-correlation signal damping
  - Clamping to [0, 100]
  - Confidence calculation in [0.0, 1.0]
  - Categorized explainable reasons (`category`, `severity`, `title`, `explanation`, `score_contribution`)
- [x] Message Threat Engine (`MessageAnalyzerService`):
  - `POST /api/v1/analyze/message` and `GET /api/v1/analyze/message/history`
  - Lexical and social engineering feature extractor (urgency, credentials, financial lures, impersonation)
  - Nested URL extraction and risk evaluation via URL Analyzer
  - Versioned message ML model (`ml/models/message_model_v1/`) with cryptographic SHA-256 validation against `metadata.json`
  - Deterministic heuristic fallback on model corruption or missing artifacts
- [x] Safe Static File Analyzer (`FileAnalyzerService`):
  - `POST /api/v1/analyze/file` and `GET /api/v1/analyze/file/history`
  - **Zero Execution Guarantee**: In-memory inspection only, zero file writes, no subprocesses
  - Magic byte sniffing (Windows PE, Linux ELF, macOS Mach-O, Office, PDF, archives)
  - Archive safety bounds: max 100 entries, max 50 MB uncompressed, 100:1 max compression ratio, traversal rejection
  - 5 MB file upload limit with dedicated 6 MB body size middleware tolerance
- [x] Unified API Endpoint (`POST /api/v1/analyze` for URL and Message vectors)
- [x] Database & Privacy Isolation:
  - `message_scans` and `file_scans` tables with Alembic migration `0005`
  - Raw message bodies and uploaded file contents are never persisted (SHA-256 only)
- [x] Frontend Multi-Vector UI (`ScannerPage.tsx`):
  - Segmented vector selector: `[ URL Scanner ] [ Message / Text ] [ Static File ]`
  - Specialized input interfaces: `MessageScanner` (with templates) and `FileScanner` (with drag & drop)
  - Rich result visualizations: `MessageScanResult` and `FileScanResult` with ThreatGauge, metadata badges, and reason cards
- [x] Comprehensive Test Suite:
  - 45 new M7 tests across 7 test suites
  - All 604 existing tests preserved and passing
  - Total: **649 passed, 0 failed** in ~43 seconds
- [x] `ruff` — zero violations
- [x] `mypy --strict` — zero violations across 94 source files


---

## Dependency decisions

| Decision | Rationale |
|----------|-----------| 
| redis-py | Standard, production-grade Redis client for Python |
| PyJWT over python-jose | python-jose has open CVEs and no releases since 2022 |
| psycopg3 over psycopg2 | Modern API, async-native, actively maintained |
| SQLAlchemy 2.x over 1.x | Fully typed `Mapped[]` API, better async support |
| pydantic v2 over v1 | Rust-backed performance, improved type safety |
| JSONB for features/reasons | Structured querying; better than TEXT for future ML queries |
| SHA-256 for URL hashing | Stable across processes; collision-resistant; no MD5 |

