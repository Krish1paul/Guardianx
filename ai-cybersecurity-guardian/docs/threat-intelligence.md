# Threat Intelligence — M4

## Overview

M4 adds an optional, failure-safe **threat-intelligence enrichment layer** to the URL analysis
pipeline. After M3 ML/rule inference produces a baseline risk score, the TI layer queries a
reputation provider and can add up to 30 additional score points for URLs flagged as
malicious or suspicious.

> [!IMPORTANT]
> **External reputation is an enrichment signal, not ground truth.**
> A clean TI result does NOT mean a URL is safe — TI databases are incomplete.
> A malicious TI result IS strong corroborating evidence, but the ML/rule baseline
> always remains the primary decision signal.

---

## Data Flow

```
POST /api/v1/analyze/url
      │
      ▼ (M2/M3 pipeline — unchanged)
1. validate + normalize + hash URL
2. extract URLFeatures
3. ML/rule inference → baseline_score [0–100], base_version
      │
      ▼ (M4 — additive enrichment)
4. ThreatIntelligenceService.enrich(url_hash, normalized_url)
      │
      ├── Cache hit (by url_hash)? → return cached result
      │
      └── Cache miss → sanitize URL (strip userinfo)
                     → provider.lookup(url_hash, safe_url)
                     → on any error → ThreatIntelResult(provider_error=True)
                     → cache successful result
      │
5. score_blender.blend(baseline_score, ti_result)
      │   MALICIOUS → +max_boost × confidence   (default up to +30)
      │   SUSPICIOUS → +(max_boost // 2) × confidence (default up to +15)
      │   CLEAN / UNKNOWN / error → +0
      │   Final score clamped to [0, 100]
      │
6. Persist URLScan + ThreatIntelligenceResult (separate table)
      │
      ▼
7. URLScanResponse(threat_intelligence=ThreatIntelSummary | None)
```

---

## Providers

### Mock Provider (default)

- **Name**: `mock`
- **When used**: `VIRUSTOTAL_API_KEY` is empty (default in development/test)
- **Network**: None — completely deterministic, no I/O
- **Classification logic**:
  - IPv4 hostname → MALICIOUS (confidence 0.90)
  - URL contains userinfo (`user:pass@host`) → SUSPICIOUS (confidence 0.75)
  - Known high-risk TLD (`.xyz`, `.tk`, `.ml`, etc.) → SUSPICIOUS (confidence 0.70)
  - Known reputable hostname (`example.com`, `google.com`, etc.) → CLEAN (confidence 0.90)
  - Anything else → UNKNOWN

### VirusTotal v3 Provider

- **Name**: `virustotal`
- **When used**: `VIRUSTOTAL_API_KEY` is set to a non-empty value
- **API**: `GET https://www.virustotal.com/api/v3/urls/{url_id}`
  - `url_id` is URL-safe base64 encoding of the sanitized URL (VT spec)
- **Authentication**: `x-apikey` header (key never logged, never in responses)
- **Classification**:
  - `malicious / total ≥ 10%` → MALICIOUS
  - Any malicious engines, or `suspicious / total ≥ 5%` → SUSPICIOUS
  - Zero malicious/suspicious → CLEAN
  - No analysis data → UNKNOWN
- **Failure modes** (all return `provider_error=True`, analysis continues):
  - Missing or empty API key
  - HTTP 401, 403, 429, 500, etc.
  - Network timeout (hard limit: `THREAT_INTEL_TIMEOUT_SECONDS`)
  - Network unreachable / DNS failure
  - Malformed / non-JSON response
  - Unexpected exception

---

## Configuration

All settings are environment variables (or `.env` file):

| Variable | Default | Description |
|----------|---------|-------------|
| `THREAT_INTEL_ENABLED` | `true` | Kill-switch — set to `false` to disable TI entirely |
| `VIRUSTOTAL_API_KEY` | `""` | API key; empty → mock provider |
| `THREAT_INTEL_TIMEOUT_SECONDS` | `5.0` | Hard network timeout per TI call |
| `THREAT_INTEL_CACHE_TTL_SECONDS` | `3600` | Cache TTL in seconds (0 = disable cache) |
| `THREAT_INTEL_MAX_BOOST` | `30` | Maximum score points TI may add to ML baseline |

---

## Privacy

### What leaves the application

| Data | Destination | Conditions |
|------|-------------|------------|
| Sanitized URL (no userinfo) | VirusTotal API | Only when `VIRUSTOTAL_API_KEY` is set |
| Nothing | Mock provider | Never makes external calls |

### What does NOT leave the application

- User identity or session data
- URL userinfo (`user:password@host` — stripped before any provider call)
- Any other user data

### What is stored locally

- `url_scans.normalized_url` — full normalized URL (M2 decision, privacy documented in model)
- `threat_intelligence_results.status/confidence/reason` — verdict only, no raw URL
- In-memory cache — entries keyed by SHA-256 hash, not raw URL. Cleared on restart.

---

## Failure Behaviour

The TI layer is fully isolated from the analysis pipeline:

| Failure | Behaviour |
|---------|-----------|
| Provider timeout | Analysis continues with ML baseline, `provider_error=True` in TI result |
| Network error | Same |
| HTTP 4xx/5xx | Same |
| Malformed response | Same |
| Missing API key | `provider_error=True`, warning logged, mock provider used on next call |
| TI kill-switch | `threat_intel_enabled=false` → TI skipped entirely |
| DB write fails for TI row | Only TI row rolls back; URLScan is committed |
| `provider_error=True` | Zero boost, no TI reason appended, `analyzer_version` unchanged |

The application will **never crash** because TI is unavailable.

---

## Caching

- In-memory LRU cache, keyed by `url_hash` (SHA-256 — never raw URL)
- Thread-safe via `threading.Lock`
- TTL eviction (lazy + periodic sweep every 100 writes)
- Max size: 10,000 entries (oldest evicted when full)
- Cache is cleared on application restart
- `threat_intelligence_results.cached=true` when a scan used a cached result

> [!NOTE]
> Redis-backed distributed caching belongs to M5. The current implementation
> is process-local — in multi-process deployments, each worker has its own cache.

---

## API Changes (Backward Compatible)

### `POST /api/v1/analyze/url` — Response

New optional field (null for M0–M3 historical scans):

```json
{
  "id": "...",
  "url": "https://example.com/",
  "risk_score": 72,
  "classification": "HIGH_RISK",
  "analyzer_version": "ml-v1+ti",
  "reasons": [
    {"code": "TI_REPUTATION", "severity": "HIGH", "message": "[mock] URL flagged as SUSPICIOUS..."}
  ],
  "threat_intelligence": {
    "provider": "virustotal",
    "status": "SUSPICIOUS",
    "confidence": 0.42,
    "reason": "3/71 engines flagged as suspicious/malicious",
    "cached": false,
    "provider_error": false,
    "checked_at": "2026-08-29T17:00:00Z"
  },
  "features": {...},
  "created_at": "2026-08-29T17:00:00Z"
}
```

### `analyzer_version` values

| Value | Meaning |
|-------|---------|
| `rule-v1` | M2 deterministic engine, no TI |
| `ml-v1` | M3 ML engine, no TI |
| `ml-v1+ti` | M3 ML engine + successful TI enrichment |
| `rule-v1+ti` | M2 rule fallback + successful TI enrichment |

**`+ti` is only appended when TI succeeded (`provider_error=False`)**. Provider errors leave the
version string unchanged.

---

## Database Schema

### `threat_intelligence_results` (new table — migration 0004)

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `scan_id` | UUID FK UNIQUE | → `url_scans.id`, CASCADE on delete |
| `provider` | VARCHAR(64) | `"virustotal"`, `"mock"` |
| `status` | VARCHAR(20) | `CLEAN`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN` |
| `confidence` | FLOAT nullable | [0.0, 1.0], null if not reported |
| `reason` | TEXT nullable | Human-readable provider reason |
| `cached` | BOOLEAN | True if served from in-memory cache |
| `provider_error` | BOOLEAN | True if provider call failed |
| `checked_at` | TIMESTAMPTZ | When the TI query was made |

Indexes: `ix_ti_scan_id`, `ix_ti_provider`

---

## Adding a New Provider

1. Create `app/services/ti_providers/your_provider.py`
2. Implement the `ThreatIntelligenceProvider` protocol:
   ```python
   class YourProvider:
       @property
       def name(self) -> str: return "your_provider"
       def lookup(self, url_hash, url, *, timeout_seconds=5.0) -> ThreatIntelResult: ...
   ```
3. Add to `app/services/ti_providers/__init__.py`
4. Wire in `app/services/url_analyzer._build_ti_service()` based on a config key
5. Add tests to `tests/test_ti_provider_interface.py`

---

## Known Limitations

> [!WARNING]
> **TI databases are incomplete.** Newly registered phishing domains may not be
> indexed. A CLEAN or UNKNOWN result is not a safety guarantee.

- Only the sanitized URL is sent to the provider — no page content, no DNS, no screenshots
- VirusTotal free API: 4 lookups/minute. Rate-limit errors return `provider_error=True`
- Cache is process-local (per M5, Redis will enable cross-process caching)
- UNKNOWN provider results generate zero boost — this is intentional (absence of evidence ≠ evidence of absence)
- IPv6 addresses not classified as malicious by mock provider (only IPv4)
