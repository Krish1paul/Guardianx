# Threat Model — AI Personal Cybersecurity Guardian

> **M2 — URL Threat Analyzer.** This document describes the threat model after M2.
> Future milestones are marked **[PLANNED]**.

---

## Scope

This threat model covers the M0–M2 backend surface:

- FastAPI HTTP server (single service)
- PostgreSQL database
- JWT authentication (M1)
- URL threat analyzer (M2)
- Configuration / secrets management
- Developer environment

---

## Assets to protect

| Asset | Classification | Notes |
|-------|---------------|-------|
| User email addresses | Sensitive PII | Stored in `users.email` |
| Password hashes | Critical | bcrypt-hashed; plain-text never stored |
| JWT secrets | Critical | Must not be committed or logged |
| Refresh tokens | Critical | SHA-256(jti) stored; raw JWTs never stored |
| Audit log integrity | Important | Must be append-only; no silently missing rows |
| Database credentials | Critical | Env-var only; no defaults in production |
| URL scan history | Sensitive | User browsing patterns; see privacy decisions |
| Normalized URLs | Sensitive PII | Stored plaintext; restricted by user_id FK |

---

## Attacker personas

### P1 — External opportunist
- **Profile**: Automated scanner, script-kiddie
- **Motivation**: Low-effort, high-scale compromise
- **Capability**: Public exploits, credential stuffing, path enumeration

### P2 — Targeted attacker
- **Profile**: Motivated individual with moderate skill
- **Motivation**: Access to a specific user's data or scan history
- **Capability**: Phishing, OSINT, known CVE exploitation, SSRF attempts

### P3 — Malicious insider
- **Profile**: Developer or operator with repository/infra access
- **Motivation**: Data exfiltration or sabotage
- **Capability**: Direct DB access, secret rotation, log tampering

### P4 — Compromised dependency
- **Profile**: Supply chain attacker via a third-party package
- **Motivation**: Credential harvest, backdoor installation
- **Capability**: Arbitrary code execution at import time

---

## STRIDE analysis — M2 attack surface (URL Analyzer)

| Threat | Category | M2 Control | Residual risk |
|--------|----------|-----------|---------------|
| SSRF via submitted URL | **E**levation | Analyzer is a pure string parser; no HTTP client calls; SSRF safety tests verify this | Very Low |
| Malicious URL that exploits the URL parser | **T**ampering | Input length capped at 2048 chars; control chars rejected before parsing; `urllib.parse` is used (not eval) | Low |
| DNS rebinding via submitted domain | **E**levation | No DNS resolution performed; static analysis only | None |
| Excessively long URL causing ReDoS | **D**enial of service | Max length enforced before regex matching; patterns use bounded quantifiers | Low |
| Unicode/IDN/punycode exploitation | **T**ampering | Punycode detected as feature; input normalized before processing | Low |
| URL encoding abuse (%2525...) | **T**ampering | Double encoding detected as HIGH_ENCODING_RATIO reason; not executed | Low |
| Log injection via URL content | **I**nformation disclosure | URL normalized and hashed before logging; raw URL not logged | Low |
| Cross-user scan access | **E**levation | `WHERE user_id = current_user.id` enforced at DB query level; tests verify isolation | Very Low |
| User supplies their own `user_id` | **S**poofing | `user_id` is NEVER read from request body — always from authenticated session | None |
| SQL injection via URL content | **T**ampering | SQLAlchemy ORM with parameterized queries; no string interpolation in queries | None |
| Sensitive URL persistence | **I**nformation disclosure | Stored per-user; TLS required; users advised about query-string PII | Low |
| Classification manipulation | **S**poofing | `classification` derived server-side from score; never accepted from client | None |

---

## M2 SSRF protection detail

SSRF (Server-Side Request Forgery) is the primary security concern for a URL analyzer.

**Protection mechanisms (defense in depth):**

1. **Architectural impossibility**: the analyzer contains no HTTP client code. There is no `requests.get()`, `httpx.get()`, or `urllib.request.urlopen()` call in the analysis path.

2. **Static analysis**: the pipeline is `string → features → score → response`. No network call is possible.

3. **Test verification**: `tests/test_url_ssrf_safety.py` monkeypatches all major HTTP libraries and `socket.create_connection` to fail if called during analysis.

4. **Documented rule**: The rule is explicit in code comments, docstrings, and this document. Any M3 or later contribution that adds a network call to the analysis path must go through security review.

**What M2 does NOT do:**
- Fetch the URL
- Resolve its DNS
- Follow redirects
- Check reputation databases (VirusTotal, Google Safe Browsing, etc.)

This is a limitation, not an oversight. See "M2 Limitations" below.

---

## M1 Authentication threat controls

| Threat | Control |
|--------|---------|
| Credential stuffing | Rate limiting (per-IP, sliding window) on `/auth/login` |
| Brute-force password attack | Rate limiting + bcrypt cost 12 |
| Session token theft/replay | Short access token lifetime (15 min); refresh token rotation |
| Refresh token reuse | Family revocation: reuse triggers invalidation of all sessions |
| Email enumeration via login | Constant-time dummy bcrypt comparison |
| Email enumeration via register | Registration returns 409 without revealing detail |
| JWT forgery | HS256 with a required minimum 32-char secret |
| Access token revocation | Deferred to M5 (Redis blocklist); mitigated by 15-min expiry |

---

## M2 Limitations

> M2 is a **deterministic heuristic analyzer** and is **not** a complete phishing or malware detection system.

**Explicitly NOT claimed:**
- AI-powered URL detection
- ML model accuracy
- Real-time website verification
- Malicious URL database coverage
- Zero false positives
- Zero false negatives

**Known limitations:**
- The analyzer cannot detect threats that require visiting the URL (hidden redirects, dynamic content, drive-by downloads).
- Legitimate URLs with many risk signals may score higher than expected (controlled by combination rules to minimize false positives).
- The suspicious TLD list is not exhaustive and may not reflect current abuse trends.
- Punycode detection identifies IDN domains but cannot verify whether a specific domain is a homograph attack.

**M3 planned improvements:**
- Trained ML classifier on labeled phishing/benign URL datasets
- Improved feature weighting based on real-world data
- Ensemble scoring (rules + ML)

---

## Privacy decisions (M2)

| Decision | Rationale | Mitigations |
|----------|-----------|-------------|
| Store `normalized_url` in plaintext | UX — users cannot identify scans from a hash | User-scoped access; TLS; no external sharing |
| Store full `features` JSONB | Enables future ML training and debugging | No external APIs; stored in user's own record |
| No URL-based external lookups | SSRF safety; privacy preservation | Limits detection capability (documented limitation) |

---

## Out of scope (M2)

| Threat | Deferred to |
|--------|------------|
| Access token server-side revocation | M5 (Redis blocklist) |
| XSS in frontend | M4 (frontend not implemented) |
| CSRF | M4 (SameSite cookies) |
| ML model poisoning | M3 |
| Data exfiltration at scale | M5 |
| Global rate limiting on scan endpoints | M5 |
| GDPR account deletion for scan history | M5 |

---

## Security controls currently active (cumulative M0–M5)

| Control | Implementation |
|---------|---------------|
| No hardcoded secrets | `pydantic-settings`; production guard enforces strength |
| Production configuration validation | Rejects weak JWT secrets (<32 chars), default DB URLs, wildcard CORS in production |
| No sequential PKs | UUID v4 on all tables |
| Password hashing | bcrypt cost 12 |
| Sensitive field & token redaction | `RedactSensitiveDataFilter` & `RedactingFormatter` (passwords, JWTs, Bearer tokens, query params) |
| Request tracing | `CorrelationIdMiddleware` sets `X-Request-ID` and `X-Correlation-ID` in headers & logs |
| Request body size protection | `BodySizeLimitMiddleware` returns HTTP 413 on oversized payloads (>1MB) |
| Centralized exception handling | Global error handler returns generic 500 without leaking stack traces or credentials |
| Security headers | `SecurityHeadersMiddleware` (nosniff, DENY, strict-origin, no-cross-domain) |
| CORS restriction | Origin allow-list |
| JWT authentication | HS256, short-lived access tokens, rotating refresh tokens |
| Refresh token family revocation | Reuse detection triggers family revocation |
| Access token revocation | Redis blocklist keyed by `revoked_jti:{jti}` with TTL matching token lifetime |
| Distributed rate limiting | `RedisRateLimiter` sliding window logs (ZSET) with `FallbackRateLimiter` safety |
| SSRF impossible by design | Pure string analysis; userinfo stripped; safe timeouts on external reputation lookups |
| Cross-user isolation | `WHERE user_id = current_user.id` enforced at database query level |
| Database connection pooling | Configurable SQLAlchemy pool (pre-ping, timeout, recycle, max overflow) |
| Container security | Multi-stage Dockerfile running as non-root `appuser:appgroup` with `HEALTHCHECK` |
| SHA-256 URL hashing | Stable, collision-resistant; Python `hash()` not used |
| Health & liveness probes | Zero-dependency `/health/live` probe and dependency-checking `/health/ready` probe |
| Zero file execution | Uploaded files are never executed, launched, or saved to the OS filesystem |
| Archive decompression bomb defense | In-memory ZIP inspection enforcing max 100 entries, 50MB uncompressed, 100:1 ratio |
| Archive path traversal protection | Disallows `..`, absolute paths (`/`, `\`), and drive letters (`C:`) in archive filenames |
| Magic byte header verification | Inspects raw file signatures without external C-library dependencies |
| Message privacy guard | Raw message/email content is never stored; only SHA-256 digest and risk signals persist |
| Cryptographic model integrity | Pickled ML models verified against trusted SHA-256 hash in metadata.json before loading |
| Fail-safe heuristic fallback | Model corruption or hash mismatch triggers automatic fallback to heuristic rules |

