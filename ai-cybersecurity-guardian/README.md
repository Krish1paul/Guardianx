# AI Personal Cybersecurity Guardian

> **Current status: M8 — Security Intelligence, Behavioral Correlation & Attack Chain Detection complete.**
> Milestones M0 through M8 are fully implemented, hardened, and verified with 677 passing tests.

A privacy-first personal cybersecurity risk platform that helps individuals and SOC analysts identify, analyze, and mitigate digital threat vectors across URLs, messages, and files.

---

## Milestone overview

| Milestone | Status | Description |
|-----------|--------|-------------|
| M0 — Foundation | ✅ Complete | Project scaffold, data models, FastAPI skeleton, CI tooling |
| M1 — Authentication | ✅ Complete | JWT auth, registration, login, refresh token rotation |
| M2 — URL Threat Analyzer | ✅ Complete | Deterministic URL risk scoring, explainable reasons, scan history |
| M3 — ML Pipeline | ✅ Complete | Phishing URL classifier, evaluation harness, explainer fallback |
| M4 — Threat Intelligence | ✅ Complete | External URL reputation, VirusTotal v3, mock provider, caching |
| M5 — Production Hardening | ✅ Complete | Redis rate limiting & revocation, DB connection pooling, health probes, Docker/CI |
| M6 — Security Dashboard | ✅ Complete | Premium SOC dark-mode dashboard, ThreatGauge, analytics, quick scan modal |
| M7 — Multi-Vector Engine | ✅ Complete | Multi-vector threat detection (URL, Message, File), explainable reasons, ML model |
| M8 — Incident Intelligence | ✅ Complete | Behavioral correlation, attack chain detection, incident lifecycle, SOC Threat Center |

---

## What is implemented (M0–M7)

### M0 — Foundation
- **FastAPI backend** with `GET /health` endpoint
- **PostgreSQL** database with `users` and `audit_logs` tables
- **SQLAlchemy 2.x** ORM models with UUID primary keys and relationships
- **Alembic** migrations (`0001_initial_schema`)
- **Security headers middleware**, **CORS**, **pydantic-settings**, **structured logging**
- **Docker Compose** with PostgreSQL + backend service

### M1 — Authentication
- `POST /api/v1/auth/register` — user registration
- `POST /api/v1/auth/login` — JWT access + refresh token pair
- `POST /api/v1/auth/refresh` — token rotation with family revocation
- `POST /api/v1/auth/logout` — refresh token revocation
- `GET /api/v1/auth/me` — authenticated user profile
- Rate limiting on all auth endpoints

### M2 — URL Threat Analyzer
- `POST /api/v1/analyze/url` — static URL threat analysis (Bearer token required)
- `GET /api/v1/analyze/url/history` — paginated scan history (user-scoped)
- Deterministic feature extraction: structural, host/domain, security, lexical
- Weighted combination-aware rule engine (avoids naive keyword matching)
- Risk score 0–100 with four tiers: `LOW_RISK` / `MEDIUM_RISK` / `HIGH_RISK` / `CRITICAL`
- Explainable structured reasons with code, severity, and message
- SHA-256 URL hashing for consistent deduplication
- **SSRF-safe by design**: no network requests are made to submitted URLs
- Cross-user scan isolation enforced at database query level
- Analyzer versioning (`rule-v1`) for M3 ML upgrade compatibility

### M3 — ML Pipeline
- 28-feature schema (`ml/features/url_feature_vector.py`)
- Logistic Regression & Random Forest classifiers trained on feature vectors
- Evaluator with ROC-AUC, Precision, Recall, and confusion matrix calculation
- Model explainer translating top features to structured reason codes
- Fail-safe fallback to deterministic heuristic rules if model artifact is missing or corrupt

### M4 — Threat Intelligence
- `ThreatIntelligenceProvider` protocol with pluggable backends
- `VirusTotalProvider` for live reputation scoring
- `MockProvider` for deterministic offline testing
- In-memory LRU hash cache with configurable TTL
- Additive score blending (0 to +30 points boost)
- Separate `threat_intelligence_results` table with 1:1 foreign key

### M5 — Production Hardening
- **Redis Integration & Rate Limiting**:
  - Pluggable `RedisClientProtocol` with thread-safe `InMemoryRedisClient` fallback.
  - `RedisRateLimiter` sliding window via Redis sorted sets (ZSET).
  - Fail-safe `FallbackRateLimiter`: if Redis fails, endpoints fall back gracefully without crashing.
- **Access-Token JTI Revocation**:
  - Access token JTIs blacklisted in Redis with TTL matching remaining validity.
  - `POST /auth/logout` revokes the caller's access token immediately.
  - Revoked access tokens are rejected with `401 Unauthorized` across all authenticated endpoints (`/auth/me`, `/analyze/url`).
- **Security & Observability**:
  - Request/Correlation ID tracing middleware (`X-Request-ID` and `X-Correlation-ID` headers + log context).
  - Safe structured logging with redacting filter & formatter (passwords, JWTs, Bearer tokens, API keys, query parameters).
  - Centralized global exception handler returning 500 without leaking internal stack traces.
  - Request body size limiter middleware (HTTP 413 on oversized payloads).
  - Production configuration validation: rejects weak JWT secrets (<32 chars), default database URLs, and wildcard CORS.
- **Health Probes**:
  - `GET /health` preserved for backward compatibility.
  - `GET /health/live` & `GET /api/v1/health/live` — zero-dependency container liveness probe.
  - `GET /health/ready` & `GET /api/v1/health/ready` — readiness probe checking PostgreSQL and Redis.
- **Database Connection Pooling**:
  - Configurable SQLAlchemy pool settings: `db_pool_size`, `db_max_overflow`, `db_pool_timeout`, `db_pool_recycle`, `db_pool_pre_ping`.
- **Hardened Docker & CI**:
  - Multi-stage Dockerfile running as non-root `appuser:appgroup` with explicit `HEALTHCHECK`.
  - Docker Compose setup including PostgreSQL 16, Redis 7 Alpine, and FastAPI backend.
  - GitHub Actions CI workflow running `ruff`, `mypy --strict`, `pytest` (>=80% coverage threshold), and Alembic check.

### M6 — Security Dashboard & Analytics
- Dark cybersecurity SOC aesthetic with custom ThreatGauge SVG radial meter.
- Real-time animated counters, scan velocity cards, and risk distribution graphs.
- Quick Scan command modal accessible via `Cmd+K` / `Ctrl+K`.
- Categorized navigation: Monitor, Analyze, and System views.

### M7 — Multi-Vector Threat Detection & Explainability
- **Unified Multi-Vector Architecture**:
  - Extensible `BaseAnalyzer` abstraction and normalized analysis result protocol.
  - Multi-vector risk scoring engine with anti-correlation damping, 0–100 clamping, and confidence estimation.
  - Explainability system generating structured reasons with threat category, severity, title, explanation, and score contribution.
- **Message / Phishing Threat Engine**:
  - `POST /api/v1/analyze/message` and `GET /api/v1/analyze/message/history`.
  - Deterministic lexical & social engineering feature extractor (urgency, credential lures, financial fraud, impersonation).
  - Safe URL extraction and nested scanning via URL Analyzer without code duplication.
  - Versioned message ML model (`ml/models/message_model_v1/`) with SHA-256 integrity verification against `metadata.json` and heuristic fallback.
- **Static File & Artifact Analyzer**:
  - `POST /api/v1/analyze/file` and `GET /api/v1/analyze/file/history`.
  - **Zero Execution Guarantee**: In-memory inspection only, no file writes to disk, no subshell execution.
  - Magic byte sniffing for PE, ELF, Mach-O, Office, PDF, and archive formats without external C-bindings.
  - Disguised binary and double-extension detection (`.pdf.exe`).
  - Safe archive inspection enforcing hard bounds: max 100 entries, max 50 MB uncompressed, max 100:1 compression ratio (ZIP bomb defense).
- **Unified API Endpoint**:
  - `POST /api/v1/analyze` handling JSON requests for URL and message vectors (files remain multipart-only).
- **Privacy-First Data Storage**:
  - Never stores raw message bodies or uploaded file contents. Only SHA-256 digests, detected metadata, and threat categories are saved.

### M8 — Security Intelligence, Behavioral Correlation & Attack Chain Detection
- **Deterministic Indicator Normalization**:
  - Offline extraction of hostnames, registrable eTLD+1 domains, SHA-256 cryptographic hashes, and sender emails.
  - Zero external DNS or network lookups during normalization to preserve analyst anonymity and guarantee SSRF safety.
- **Explainable Correlation Engine**:
  - Correlates individual URL, Message, and File scans into consolidated `Incident` and `IncidentEvent` entities.
  - Categorizes attack stages: `RECONNAISSANCE`, `INITIAL_ACCESS`, `CREDENTIAL_HARVESTING`, `MALICIOUS_DELIVERY`, `EVASION_EXECUTION`, `SOCIAL_ENGINEERING`, `MULTI_VECTOR_CAMPAIGN`.
  - Non-linear diminishing returns risk score calculation: each subsequent attack vector contributes incrementally, strictly clamped to $[0, 100]$.
  - Explainable detection reasons with calibrated confidence scores and clear rationale.
- **Behavioral Sequence Analyzer**:
  - Heuristic detection of rapid repeat activity within short time windows (<=5 min).
  - Severity escalation detection (e.g. Medium Risk initial contact escalating to Critical payload delivery).
  - Multi-vector campaign sequence identification (Phishing message -> Embedded URL -> Malicious file).
- **Incident Lifecycle REST APIs**:
  - `GET /api/v1/incidents` — filterable by status (`OPEN`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`) with user tenancy enforcement.
  - `GET /api/v1/incidents/{id}` — detailed view with indicators, explainable reasons, and behavioral summary.
  - `PATCH /api/v1/incidents/{id}/status` — lifecycle transitions.
  - `GET /api/v1/incidents/{id}/timeline` — chronological attack chain timeline with resolved scan metadata.
- **SOC Threat & Incident Center**:
  - Dark-mode Incident Intelligence UI with KPI summary strips, filter tabs, and interactive attack chain inspection modals.
  - Chronological vertical attack chain timeline with vector icons and risk score contribution badges.

---

## Repository layout

```
.
├── backend/                # FastAPI application
│   ├── app/
│   │   ├── api/v1/         # HTTP route handlers (auth, analyze_url, analyze_message, analyze_file, analyze_unified, health)
│   │   ├── core/           # Config, logging, security, redis, rate_limit, url_utils
│   │   ├── db/             # SQLAlchemy engine, session & connection pooling
│   │   ├── middleware/     # Security headers, correlation ID, body size limit
│   │   ├── models/         # ORM models (User, AuditLog, RefreshToken, URLScan, MessageScan, FileScan, ThreatIntel)
│   │   ├── schemas/        # Pydantic schemas (auth, url_analysis, unified_analysis, health)
│   │   ├── services/       # Auth, URL analyzer, Message analyzer, File analyzer, UnifiedRiskEngine, TI
│   │   └── main.py         # FastAPI app factory & global exception handlers
│   ├── tests/              # Comprehensive test suite (649 tests)
│   ├── alembic/            # Database migrations (0001-0005)
│   ├── Dockerfile          # Hardened multi-stage non-root container
│   └── pyproject.toml
├── frontend/               # React 18 + Vite + TypeScript SOC dashboard
│   ├── src/
│   │   ├── components/     # UI widgets, ThreatGauge, Scanner (URL, Message, File)
│   │   ├── pages/          # Dashboard, Scanner, Threat Center, Analytics, History
│   │   ├── lib/            # Axios API client, auth store, utilities
│   │   └── types/          # TypeScript schemas mirroring backend models
├── ml/
│   ├── datasets/           # Synthetic fixtures (URL and message)
│   ├── features/           # URL, message, and file feature extractors
│   ├── inference/          # URL and message inference engines with hash checks
│   ├── models/             # Versioned model artifacts (url_model_v1, message_model_v1)
│   ├── training/           # Model training scripts
│   └── evaluation/         # Evaluation harness
├── docs/                   # Architecture, Threat Model, Database, ML Pipeline, Roadmap
├── docker-compose.yml       # Production/development orchestration
├── .github/workflows/ci.yml # GitHub Actions CI pipeline
└── README.md
```


---

## Quick start

### Prerequisites

- Python 3.11+
- Docker and Docker Compose

### 1. Configure environment

```bash
cp .env.example .env
# Edit .env - set POSTGRES_PASSWORD and JWT_SECRET at minimum
```

### 2. Start infrastructure (Postgres + Redis)

```bash
docker compose up -d db redis
```

### 3. Set up the backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 4. Apply migrations

```bash
cd backend
alembic upgrade head
```

### 5. Start the API

```bash
uvicorn app.main:app --reload
```

---

## Development commands

```bash
# Linting
python3 -m ruff check app/ tests/

# Type checking
python3 -m mypy app/ tests/

# Tests & Coverage
python3 -m pytest tests/ --cov=app --cov-fail-under=80 -v

# Alembic migration verification
alembic check
alembic heads
```

---

## Documentation

- [Architecture](docs/architecture.md)
- [Database schema](docs/database.md)
- [Development roadmap](docs/development-roadmap.md)
- [Threat model](docs/threat-model.md)
- [Threat intelligence](docs/threat-intelligence.md)
- [ML pipeline](docs/ml-pipeline.md)

---

## Security

- No secrets are hardcoded — all configuration loaded from environment variables
- Production startup rejects missing or weak JWT secrets, wildcard CORS, and default DB credentials
- Passwords hashed with bcrypt (cost factor 12)
- HTTP security headers (nosniff, DENY, strict-origin, no-cross-domain)
- Request body size limits (HTTP 413) to prevent DoS
- Access token revocation via Redis blocklist
- Redaction of passwords, tokens, API keys, and sensitive query strings in logs
- SSRF impossible by design — URL analyzer makes no network requests to target hosts
- Cross-user data isolation enforced at database query level

---

## License

MIT - see [LICENSE](LICENSE).
