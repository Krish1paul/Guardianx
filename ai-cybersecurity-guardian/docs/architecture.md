# Architecture — AI Personal Cybersecurity Guardian

> **M5 — Production Hardening.** This document describes the architecture as it exists after M5.
> Sections covering future milestones are clearly marked **[PLANNED]**.

---

## Current state (M5)

The system is a single-service FastAPI backend backed by PostgreSQL 16 and Redis 7,
with JWT-based authentication (M1), a URL threat analyzer (M2), an
ML-powered URL classifier (M3) using a trained Logistic Regression / Random Forest
pipeline, a failure-safe threat-intelligence enrichment layer (M4), and a hardened
production runtime with Redis rate limiting, access-token JTI revocation, DB connection
pooling, health probes, and security middleware (M5).

```
┌────────────────────────────────────────────────────────────────────┐
│  Client (curl, Postman, frontend, tests)                           │
└────────────────────────┬───────────────────────────────────────────┘
                         │ HTTPS (with X-Request-ID / X-Correlation-ID)
                         ▼
┌────────────────────────────────────────────────────────────────────┐
│  FastAPI backend  (Python 3.11, Uvicorn)                           │
│                                                                    │
│  Middleware stack (outermost → innermost):                         │
│    CorrelationIdMiddleware    ─ X-Request-ID / X-Correlation-ID    │
│    TrustedHostMiddleware      ─ Host header validation (prod)      │
│    SecurityHeadersMiddleware  ─ X-Frame-Options, HSTS, etc.        │
│    BodySizeLimitMiddleware    ─ Content-Length & stream size cap   │
│    CORSMiddleware             ─ Origin allow-list                  │
│                                                                    │
│  Routes:                                                           │
│    GET  /health                  → HealthResponse                  │
│    GET  /health/live             → LivenessResponse  [M5]          │
│    GET  /health/ready            → ReadinessResponse [M5]          │
│    GET  /api/v1/health           → HealthResponse                  │
│    GET  /api/v1/health/live      → LivenessResponse  [M5]          │
│    GET  /api/v1/health/ready     → ReadinessResponse [M5]          │
│    POST /api/v1/auth/register    → UserMeResponse                  │
│    POST /api/v1/auth/login       → TokenPair                       │
│    POST /api/v1/auth/refresh     → TokenPair                       │
│    POST /api/v1/auth/logout      → 204 (Revokes access & refresh)  │
│    GET  /api/v1/auth/me          → UserMeResponse (Revocation check)│
│    POST /api/v1/analyze/url      → URLScanResponse  [M2/M3/M4]     │
│    GET  /api/v1/analyze/url/history → URLScanHistoryResponse [M2]  │
│    POST /api/v1/analyze/message  → MessageScanResponse [M7]        │
│    GET  /api/v1/analyze/message/history → MessageScanHistory [M7]   │
│    POST /api/v1/analyze/file     → FileScanResponse [M7]           │
│    GET  /api/v1/analyze/file/history → FileScanHistory [M7]        │
│    POST /api/v1/analyze          → UnifiedScanResponse [M7]        │
│                                                                    │
│  Core modules & Analyzers:                                         │
│    core/config.py         ─ pydantic-settings & prod validator     │
│    core/logging.py        ─ structured log + redacting formatter   │
│    core/security.py       ─ bcrypt hashing                         │
│    core/auth.py           ─ JWT creation / verification            │
│    core/redis.py          ─ Redis client protocol & in-memory mock │
│    core/rate_limit.py     ─ Redis ZSET + in-memory fallback limiter│
│    services/token_revocation.py ─ Redis JTI blocklist with TTL     │
│    core/url_utils.py      ─ URL validation, normalization, SHA-256 │
│    services/analyzers/    ─ BaseAnalyzer & UnifiedRiskEngine [M7]  │
│    services/analyzers/url_analyzer.py ─ Multi-vector URL adapter   │
│    services/analyzers/message_analyzer.py ─ Social eng & links [M7]│
│    services/analyzers/file_analyzer.py ─ Safe static file analyzer │
└────────────────────────┬─────────────────────┬─────────────────────┘
                         │ SQLAlchemy 2.x      │ redis-py (ZSET/TTL)
                         ▼                     ▼
┌──────────────────────────────────────┐  ┌──────────────────────────┐
│  PostgreSQL 16                       │  │  Redis 7                 │
│    users                             │  │    ratelimit:*           │
│    audit_logs                        │  │    revoked_jti:*         │
│    refresh_tokens                    │  │    threat_intel_cache:*  │
│    url_scans                         │  └──────────────────────────┘
│    message_scans              [M7]   │
│    file_scans                 [M7]   │
│    threat_intelligence_results       │
└──────────────────────────────────────┘
```

---

## M2 — URL Threat Analyzer

### Pipeline

```
Raw URL string
     │
     ▼
app/core/url_utils.py — validate_url()
     │  Rejects: disallowed schemes, control chars,
     │           oversized input, malformed structure
     ▼
app/core/url_utils.py — normalize_url()
     │  Lowercases hostname/scheme, removes default ports,
     │  collapses path slashes, removes fragment
     ▼
app/core/url_utils.py — hash_url()  [SHA-256]
     │
     ▼
ml/features/url_features.py — extract()
     │  Pure stateless extraction:
     │    Structural, Host/Domain, Security, Lexical features
     ▼
ml/inference/url_inference.py — URLInferenceEngine.run()
     │  M2: delegates to URLRiskEngine (deterministic rule fallback)
     │  M3: trained ML model (Logistic Regression / Random Forest)
     │  Returns: score (0–100) + classification + reasons + analyzer_version
     ▼
app/services/threat_intelligence.py — ThreatIntelligenceService.enrich()  [M4]
     │  Cache lookup (by url_hash, SHA-256)
     │  Provider.lookup() — mock (default) or VirusTotal
     │  On any error → provider_error=True, analysis continues
     ▼
app/services/score_blender.py — blend()  [M4]
     │  MALICIOUS → +up to max_boost points
     │  SUSPICIOUS → +up to max_boost//2 points
     │  CLEAN/UNKNOWN/error → +0
     │  Result clamped to [0, 100]
     ▼
app/services/url_analyzer.py — URLAnalyzerService.analyze()
     │  Persists URLScan row + ThreatIntelligenceResult row
     ▼
app/api/v1/analyze_url.py
     │  Returns URLScanResponse (+ optional threat_intelligence field)
     ▼
Client
```

### SSRF protection

The M3 URL analyzer is a **static string parser with ML inference**. It never:
- Fetches the submitted URL
- Resolves DNS
- Follows redirects
- Downloads content

This is enforced by design and verified by dedicated SSRF safety tests
(`tests/test_url_ssrf_safety.py`, `tests/test_url_model_security.py`) that
monkeypatch all HTTP client libraries and verify no network calls occur.

### M3 ML inference path

The single upgrade boundary is `ml/inference/url_inference.py`.
M3 replaces the M2 rule engine with a trained ML classifier:

```
URLFeatures → url_feature_vector.features_to_vector() → [float; 28]
     ↓
ML Pipeline (StandardScaler + LogisticRegression/RandomForest)
     ↓
P(malicious) ∈ [0, 1]  →  risk_score = round(P × 100)
     ↓
URLExplainer → list[RiskReason]  (feature importances → security reasons)
     ↓
URLRiskResult(score, classification, reasons, analyzer_version="ml-v1")
```

**Fallback**: if the ML model artifact is missing or has a schema mismatch,
the engine falls back to the M2 rule engine with `analyzer_version="rule-v1"`.

---

## M1 — Authentication layer

```
Client → POST /api/v1/auth/register   → UserMeResponse
       → POST /api/v1/auth/login      → TokenPair (access + refresh JWT)
       → POST /api/v1/auth/refresh    → TokenPair (rotated)
       → POST /api/v1/auth/logout     → 204
       → GET  /api/v1/auth/me         → UserMeResponse
```

JWT access tokens (15 min) and rotating refresh tokens (7 days).
Refresh token families prevent reuse attacks.
Rate limiting on all auth endpoints.

---

## Technology choices

| Component | Technology | Version | Rationale |
|-----------|-----------|---------|-----------| 
| Language | Python | 3.11+ | Mature async support, rich ML ecosystem |
| Web framework | FastAPI | ≥ 0.115 | Auto OpenAPI, async-native, pydantic integration |
| ASGI server | Uvicorn | ≥ 0.30 | High-performance ASGI |
| ORM | SQLAlchemy | 2.x | Fully typed, async-capable, alembic integration |
| DB driver | psycopg3 (binary) | ≥ 3.2 | Modern PostgreSQL driver, async support |
| Migrations | Alembic | ≥ 1.13 | Paired with SQLAlchemy, supports autogenerate |
| Config | pydantic-settings | ≥ 2.4 | Typed config from env vars, `.env` support |
| Validation | Pydantic v2 | ≥ 2.8 | Fast, Rust-backed validation |
| Hashing | bcrypt | ≥ 4.1 | Industry standard, cost-configurable |
| JWT | PyJWT | ≥ 2.9 | Actively maintained; replaces abandoned python-jose |
| Database | PostgreSQL | 16 | ACID, UUID support, JSONB for feature storage |

---

## Planned architecture (M3+)

| ML framework | scikit-learn | ≥ 1.3 | Lightweight, no CUDA required, joblib persistence |
| Model persistence | joblib | ≥ 1.3 | Efficient sklearn Pipeline serialization |

---

## M3 — ML Pipeline (implemented)

```
ml/
├── datasets/
│   ├── README.md              ← dataset format, sources, privacy
│   └── fixtures/sample_urls.csv  ← synthetic fixture (NOT production)
├── preprocessing/url_dataset.py  ← load, validate, dedup, split
├── features/
│   ├── url_features.py        ← M2 URLFeatures (unchanged)
│   └── url_feature_vector.py  ← stable 28-column numeric schema
├── training/train_url_model.py   ← train LR + RF, select by recall
├── evaluation/evaluate.py        ← metrics, threshold search
├── inference/
│   ├── url_inference.py       ← M3 swap point (ML + rule-v1 fallback)
│   └── url_explainer.py       ← feature importances → RiskReason list
└── models/url_model_v1/
    ├── model.pkl              ← trained sklearn Pipeline (gitignored)
    ├── metadata.json          ← training config + metrics
    └── feature_schema.json    ← feature names + schema version
```

See `docs/ml-pipeline.md` for full documentation.

---

## [PLANNED] M4 — Frontend Dashboard

```
frontend/   — React (Vite) SPA
  Dashboard — risk overview, scan history
  Alerts    — active threat notifications
  Settings  — profile, MFA, data export
```

---

## Design principles

1. **Privacy-first**: user data never leaves the deployment; no analytics beacons.
2. **Fail-secure**: if a required secret is missing in production the server refuses to start.
3. **Audit by default**: every significant action creates an `audit_log` row.
4. **Separation of concerns**: routes → services → ML layer → feature extraction.
5. **Typed everywhere**: `mypy --strict` on the entire codebase from day one.
6. **SSRF-impossible**: static analyzer design makes URL fetching architecturally impossible.
7. **Explainable by default**: every risk score is backed by structured, human-readable reasons.
