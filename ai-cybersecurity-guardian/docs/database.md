# Database — AI Personal Cybersecurity Guardian

> **M2 — URL Threat Analyzer.** This document describes the database schema after M2.

---

## Overview

- **Database**: PostgreSQL 16
- **ORM**: SQLAlchemy 2.x with `DeclarativeBase`
- **Driver**: `psycopg[binary]` (psycopg3)
- **Migrations**: Alembic (`alembic upgrade head`)
- **Primary keys**: UUID v4 throughout

---

## Tables

### `users`

Stores registered user accounts.

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | `UUID` | PK, default `uuid4()` | |
| `email` | `VARCHAR(255)` | NOT NULL, UNIQUE, INDEX | Normalised to lowercase |
| `password_hash` | `VARCHAR(255)` | NOT NULL | bcrypt, cost 12 |
| `created_at` | `TIMESTAMPTZ` | NOT NULL, default `now()` | UTC |
| `mfa_enabled` | `BOOLEAN` | NOT NULL, default `false` | TOTP-based MFA |
| `last_login_at` | `TIMESTAMPTZ` | NULL | Updated on each successful login |

---

### `audit_logs`

Immutable append-only audit trail. Rows survive user deletion (`ON DELETE SET NULL` on `user_id`).

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | `UUID` | PK, default `uuid4()` | |
| `user_id` | `UUID` | FK → `users.id` ON DELETE SET NULL, NULL allowed | NULL means system or deleted user |
| `actor` | `VARCHAR(255)` | NOT NULL | Human-readable identifier |
| `action` | `VARCHAR(100)` | NOT NULL | e.g. `url.scan`, `auth.login` |
| `resource` | `VARCHAR(255)` | NOT NULL | Target resource identifier |
| `ip_address` | `VARCHAR(45)` | NULL | IPv4 or IPv6 |
| `created_at` | `TIMESTAMPTZ` | NOT NULL, default `now()` | UTC |

**Indexes**
- `ix_audit_logs_user_id_created_at` — composite (user_id, created_at)
- `ix_audit_logs_action` — action-type filtering

---

### `refresh_tokens`

Server-side refresh token store for secure JWT rotation.

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | `UUID` | PK | |
| `user_id` | `UUID` | FK → `users.id` ON DELETE CASCADE | |
| `token_hash` | `VARCHAR(64)` | NOT NULL, UNIQUE | SHA-256(jti) |
| `family_id` | `UUID` | NOT NULL | Rotation chain grouping |
| `expires_at` | `TIMESTAMPTZ` | NOT NULL | |
| `created_at` | `TIMESTAMPTZ` | NOT NULL, default `now()` | |
| `revoked_at` | `TIMESTAMPTZ` | NULL | NULL = active |

---

### `url_scans` *(M2)*

Persisted URL analysis results. One row per scan per user.

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | `UUID` | PK, default `uuid4()` | |
| `user_id` | `UUID` | FK → `users.id` ON DELETE CASCADE, INDEX | |
| `url_hash` | `VARCHAR(64)` | NOT NULL, INDEX | SHA-256 of normalized URL |
| `normalized_url` | `TEXT` | NOT NULL | See privacy note below |
| `risk_score` | `INTEGER` | NOT NULL | 0–100 |
| `classification` | `VARCHAR(20)` | NOT NULL | `LOW_RISK` / `MEDIUM_RISK` / `HIGH_RISK` / `CRITICAL` |
| `features` | `JSONB` | NOT NULL | Full `URLFeatures` dict |
| `reasons` | `JSONB` | NOT NULL | List of `RiskReason` objects |
| `analyzer_version` | `VARCHAR(32)` | NOT NULL, default `rule-v1` | `rule-v1` (M2), `ml-v1` (M3) |
| `created_at` | `TIMESTAMPTZ` | NOT NULL, default `now()` | UTC |

**Indexes**
- `ix_url_scans_user_id` — all scans for a user
- `ix_url_scans_url_hash` — deduplication lookup
- `ix_url_scans_user_id_created_at` — composite for history queries (newest-first)

**Privacy decision — `normalized_url`**

`normalized_url` is stored in plaintext. This is a deliberate, documented decision:

- **Rationale**: Users cannot identify past scans from a SHA-256 hash alone. The URL is required for a usable history view.
- **Mitigation**: The service enforces `WHERE user_id = current_user.id` at the query level. No user can read another user's scans.
- **Limitation**: URLs may contain PII (search queries, tokens). Users should be advised not to submit URLs containing sensitive tokens in query strings.
- **Future**: M5 will add configurable URL redaction and GDPR data-export controls.

**JSONB usage**

`features` and `reasons` are stored as JSONB (PostgreSQL) to enable future structured querying and indexing on specific feature values (e.g., `WHERE features->>'is_ip_address' = 'true'`).

---

## Entity relationships

```
users
  id (PK) ──────────┬──────────────┐
  email             │              │
  password_hash     │              │
  created_at        │              │
  mfa_enabled       │              │
  last_login_at     │              │
                    │              │
audit_logs          │              │
  id (PK)           │              │
  user_id (FK) ─────┘ SET NULL     │
  actor                            │
  action                           │
  resource                         │
  ip_address                       │
  created_at                       │
                                   │
refresh_tokens                     │
  id (PK)                          │
  user_id (FK) ────────────────────┤ ON DELETE CASCADE
  token_hash                       │
  family_id                        │
  expires_at                       │
  revoked_at                       │
                                   │
url_scans  [M2]                    │
  id (PK)                          │
  user_id (FK) ────────────────────┘ ON DELETE CASCADE
  url_hash
  normalized_url
  risk_score
  classification
  features (JSONB)
  reasons  (JSONB)
  analyzer_version
  created_at
```

---

## SQLAlchemy models

- [`app/models/user.py`](../backend/app/models/user.py) — `User`
- [`app/models/audit_log.py`](../backend/app/models/audit_log.py) — `AuditLog`
- [`app/models/refresh_token.py`](../backend/app/models/refresh_token.py) — `RefreshToken`
- [`app/models/url_scan.py`](../backend/app/models/url_scan.py) — `URLScan` *(M2)*
- [`app/db/base.py`](../backend/app/db/base.py) — `DeclarativeBase`

---

## Migrations

### Apply migrations

```bash
cd backend
alembic upgrade head
```

### Migration history

| Revision | Description |
|----------|-------------|
| `0001` | Initial schema — creates `users` and `audit_logs` |
| `0002` | Add `refresh_tokens` table — M1 Authentication |
| `0003` | Add `url_scans` table — M2 URL Threat Analyzer |

---

## Design decisions

- **UUID primary keys**: avoids sequential ID enumeration attacks.
- **`ON DELETE SET NULL` (audit_logs)**: audit trail is permanent; deleting a user does not destroy evidence.
- **`ON DELETE CASCADE` (refresh_tokens, url_scans)**: scan and session data are personal and should be removed with the user.
- **`TIMESTAMPTZ`**: all timestamps include timezone offset; stored as UTC.
- **JSONB for features/reasons**: enables future structured queries; performs better than TEXT JSON on PostgreSQL.
- **SHA-256 for `url_hash`**: stable across processes, collision-resistant, not reversible via rainbow tables (unlike MD5).
- **`analyzer_version` is immutable**: historical records preserve their provenance. M3 records use `ml-v1`; M2 records permanently show `rule-v1`.
