# SENTINEL — Evidence-Driven Security Operations

**Standalone · Local-first · Zero mandatory paid subscriptions · Pre-production v0.8.0 development branch**

> **Implementation status:** a functioning local security event ingestion and detection core, operator dashboard source, and automated backend tests. **Not yet a complete SOC, EDR, antivirus, firewall, commercial security replacement, attacker-tracing tool or offensive platform.** No claim of enterprise certification or live network protection is made.

SENTINEL explores how security telemetry, deterministic rules, traceable incident evidence and constrained AI-assisted investigation can evolve into a verifiable defense platform. This initial release deliberately has **no destructive, retaliatory or live network enforcement features**.

## Synthetic detection qualification (v0.8)

Run from backend after installing the declared test dependencies:

```bash
python -m scripts.benchmark_quality --json synthetic-quality-results.json
```

The benchmark exercises **real signed ingestion, deterministic detection, alert
storage and audit verification** against a fresh temporary migrated SQLite
database for each of 15 explicit positive/negative cases. It fails on missing
or unexpected alerts. GitHub CI stores an ephemeral machine-readable report.

**All reported precision, recall, false-positive scenario counts and in-process
TestClient timings are synthetic regression measurements only.** They are not
real-world detection rates, network or sensor latency, performance SLAs or claims
of production readiness. A real-world labeled evaluation dataset and independent
traffic capture benchmark remain necessary.

## What is actually implemented

| Module | Status | Evidence |
| --- | --- | --- |
| HMAC-authenticated sensor ingestion | Implemented | `backend/sentinel/app.py`, signed requests and tests |
| Replay resistance + size/schema limits | Implemented | `backend/tests/test_api.py` |
| Failed-login burst detection | Implemented | `backend/sentinel/detection.py` |
| Network-denied burst, malware indicator and denied elevation rules | Implemented | Deterministic rules and tests |
| Alert/evidence correlation | Implemented | `/api/v1/alerts/{id}/evidence` |
| HMAC-linked local audit, triage integrity cross-check | Implemented with documented limitations | `backend/sentinel/audit.py` |
| Authenticated telemetry read APIs | Implemented | `/api/v1/overview`, `/alerts`, `/events` |
| Manual analyst incident triage | Implemented for local lab | Explicit state transitions, reasons, recorded decision history, tests |
| Premium operator dashboard | CI production build passed in prior v0.4 PR; interactive accessibility not verified | `frontend/app` |
| Linux SSH authentication-log collector | Implemented; bounded, read-only, localhost-only | `backend/sentinel/collectors/linux_ssh.py`, integration tests |
| Explicit database migrations + serialized audit head (v0.5) | Implemented locally; PostgreSQL qualification requires CI | `backend/migrations`, `backend/tests/test_migrations_audit.py` |
| Signed SQLite backup, audit-verified snapshot and new-file offline recovery (v0.6) | Implemented in local test environment | `backend/sentinel/backup.py`, `backend/tests/test_backup_recovery.py` |
| Opt-in expiring/revocable operator credentials (v0.7) | Implemented with offline local administration, no MFA or HTTP provisioning | `backend/sentinel/credential_lifecycle.py`, `backend/tests/test_credential_lifecycle.py` |
| Wazuh/Suricata and general endpoint agents | **Not implemented** | Planned |
| Automated blocking, network protection or honeypots | **Not implemented** | Planned with approval gates |
| AI-powered investigation and threat graph | **Not implemented** | Planned |

## Individual operator access (v0.4 development)

The new optional `SENTINEL_OPERATORS` JSON environment mapping enrolls distinct
`viewer`, `analyst` and `admin` identities using SHA-256 digests of generated
high-entropy bearer tokens. It disables legacy shared-token fallback when configured.
The server enforces triage and audit permissions and attributes decisions to the
actual enrolled operator ID. See [identity and access](docs/IDENTITY_AND_ACCESS.md).
This is **not** MFA, SSO, or Internet-safe user management; it is a local MVP
improvement, not an enterprise identity solution. `GET /api/v1/session` returns
non-secret role and capability details for the dashboard.

## Architecture

```text
Lab event emitter / opt-in Linux SSH auth-log collector (other sensors planned)
   │ signed timestamp + unique nonce + payload HMAC
   ▼
FastAPI signed event ingestion ──► schema validation and bounded payloads
   │
   ▼
SQLite (default) / PostgreSQL (optional migration-tested target)
   │
   ├── Security events
   ├── Deterministic detection → Alerts → Evidence links
   ├── HMAC-chained local audit records
   └── Alert decision history (with hashed audit references)
   │
   ▼
Authenticated analyst API ◄── Next.js operator dashboard
```

The SSH collector uses normalized collection timestamps (not necessarily original event timestamps) and is restricted to local authorized log files. It is not an endpoint protection agent and does not detect all authentication threats.

Full rationale: [Architecture](docs/ARCHITECTURE.md) · [Threat model](docs/THREAT_MODEL.md) · [Security policy](SECURITY.md)

## Quick start — Linux/macOS (Python 3.11+, Node.js 22+)

**1. Create credentials.** Copy the template into `.env`, then replace all three secrets with the generated output (keep the database/origin lines).

```bash
cp .env.example .env
python3 backend/scripts/generate_keys.py
# Edit .env: replace the three placeholder values with output above.
# Protect .env, do not commit it.
```

**2. Start the backend.** The provided local SQLite backend starts without Docker or a hosted database.

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
cd ..
set -a; source .env; set +a
cd backend
python -m alembic -c alembic.ini upgrade head
uvicorn sentinel.main:app --host 127.0.0.1 --port 8000
```

Open a second terminal **with the project environment loaded**:

```bash
cd sentinel-security-platform
set -a; source .env; set +a
python3 backend/scripts/send_demo_events.py
```

Five signed, synthetic login failures from reserved example IP `198.51.100.42` will create **one real deterministic alert**. This script never sends exploit traffic or contacts that documentation IP; it sends JSON to your own localhost server.

**3. Launch the dashboard** (Node.js required; frontend dependencies must be installed from npm):

```bash
cd frontend
npm install
npm run dev
# Open http://localhost:3000, enter SENTINEL_OPERATOR_TOKEN from .env
```

The operator token stays in tab memory and must be re-entered after reload. The web app fetches observed data; it does not manufacture alerts or inflate metrics. Operators can now investigate, resolve or reopen findings with a mandatory documented rationale, without triggering firewall or endpoint enforcement.


### Explicit database migrations (v0.5)

**New installation:** with credentials loaded in the terminal, run `cd backend && python -m alembic -c alembic.ini upgrade head` **before starting the API**. The API now fails closed when its database revision does not match the expected schema. It never silently creates or mutates production tables on startup. New databases receive legacy schema revision `0001_initial` followed by the serialized audit-head revision `0002_audit_head`. Re-running `upgrade head` is idempotent.

**Existing v0.4 SQLite with evidence you must retain:** stop all Sentinel processes, keep existing HMAC audit key, and perform the guarded offline baseline-and-upgrade using a **new backup path**:

```bash
cd backend
python scripts/upgrade_legacy_db.py \
  --database /absolute/path/to/old/sentinel.db \
  --backup /absolute/private/path/to/sentinel-v04-backup.db \
  --confirm-offline
```

The utility checks legacy table structure, verifies the full HMAC audit chain and triage history, creates a private SQLite backup, then stamps `0001_initial` and runs the auditable `0002_audit_head` migration. It refuses suspicious schema drift, wrong keys, mismatched histories and existing version markers. It **does not** handle a live database: stop all writers and retain a separate offline backup outside the monitored system. New databases should **never** use the legacy utility. PostgreSQL is tested in ephemeral CI for schema upgrades and concurrent requests; no claim of high availability, production capacity, online migrations or cross-region durability is made.

**Audit concurrency:** the audit head is a transaction-scoped locking point. On PostgreSQL, `SELECT FOR UPDATE` serializes writes; on SQLite, an explicit write lock precedes event evaluation. The audit chain is checked against the stored head's last hash and count. This detects several classes of in-database deletion and chain forks but **does not provide independent append-only storage or resistance to an attacker who owns the database and the audit secret**.


### SQLite backup and offline recovery (v0.6)

The optional SQLite-only maintenance utility uses SQLite's online backup API to take a consistent snapshot (including committed WAL data). The snapshot is checked for database integrity, the expected migration revision, the complete HMAC-linked audit chain and case decisions. A private manifest records its checksum and audit head and is authenticated with \`SENTINEL_AUDIT_KEY\`.

Run from the backend virtual environment, with the audit key loaded and a **private parent directory** under your control:

\`\`\`bash
mkdir -p "$HOME/sentinel-backups"
chmod 700 "$HOME/sentinel-backups"
cd backend
python scripts/sqlite_recovery.py backup ./sentinel.db "$HOME/sentinel-backups/backup-001"
python scripts/sqlite_recovery.py verify "$HOME/sentinel-backups/backup-001"

# For a recovery drill, STOP the API and all database writers first.
python scripts/sqlite_recovery.py restore "$HOME/sentinel-backups/backup-001" ./restored-sentinel.db
\`\`\`

Backup directories are created new with restrictive permissions. Restore never overwrites an existing target. The operator must ensure the API is stopped for restore; this tool cannot enforce process isolation. **Backups are not encrypted, immutable, remotely replicated, automatically scheduled, or PostgreSQL-compatible.** Retain the audit key separately; losing or rotating it without a retention plan makes old backup verification impossible. Maintain independent protected off-host copies and run documented restore drills before relying on the system.

### Linux SSH auth-log collector (optional real telemetry)

Run this **only on a Linux machine you administer and have permission to monitor**. The core API must already be running locally at `127.0.0.1:8000`. The collector never opens outbound connections or takes defensive action. Access to `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (many RHEL-based distributions) is required; use a narrowly scoped read group or managed service account rather than running the whole Sentinel stack as root.

```bash
# With the same sensor environment variables loaded as the backend:
mkdir -p "$HOME/.local/state/sentinel"
chmod 700 "$HOME/.local/state/sentinel"
cd backend
python -m sentinel.collectors.linux_ssh \
  --source /var/log/auth.log \
  --state "$HOME/.local/state/sentinel/ssh-cursor.json" \
  --asset workstation-1 --sensor lab-sensor-1
# Add --follow --interval 5 for ongoing polling, after first verifying a one-shot run.
```

The collector starts at **the end of the current file** on first enrollment, avoiding misleading alerts from old logs. To explicitly reprocess historical lines in a controlled lab, pass `--backfill`. Existing cursor state is resumed regardless of this flag.

The `--sensor` value must match a key in `SENTINEL_SENSOR_KEYS`. All source and state paths must be absolute; the log source must be a regular file that is not writable by group or others. The cursor directory must be private (`0700`), and the state file is atomically updated (`0600`). A source rotation or truncation resets the cursor generation to prevent nonce collisions. Retries reuse position-derived HMAC nonces; **HTTP 409** indicates that the event was already accepted by the local ingestion API. An acknowledgement followed by a crash can cause a retry, not a second stored event.

**Privacy/accuracy:** only source IP, asset, event action and UTC collection time are transmitted, **not usernames, passwords, ports or raw log lines**. The parser recognizes a limited SSHD failure format and may miss formats used by other Linux distributions or configurations; it does not verify that log text is truthful or that a source IP identifies a person. Old historical lines get current collection timestamps and can produce misleading bursts if backfilled; start with a rotated/fresh log and review results before enabling continuous collection. An incomplete last line is retried; malformed or oversized lines stop the collector safely for operator review. No unattended service installation is performed.

### Windows PowerShell alternative

Create the venv with `py -m venv .venv` and activate with `.venv\Scripts\Activate.ps1`. Set environment variables using `$env:SENTINEL_OPERATOR_TOKEN=...`, `$env:SENTINEL_AUDIT_KEY=...`, `$env:SENTINEL_SENSOR_KEYS='{"lab-sensor-1":"..."}'` in the backend terminal before running `uvicorn`. Repeat the sensor variable in the demo sender terminal. `.env` is not auto-loaded by Python.

## Backend test suite

```bash
cd backend
python -m pip install -e '.[test]'
python -m pytest -q
```

Tests use isolated temporary SQLite databases, local SSH log fixtures, and random event nonces. The sensor integration test verifies that five normalized log entries trigger a real correlated alert. They require no cloud credentials. CI runs backend tests and attempts frontend type checks and build separately.

## Operator API (localhost only)

- `GET /api/v1/health`: non-sensitive health status.
- `POST /api/v1/events`: HMAC-signed sensor ingestion, HTTP 202.
- `GET /api/v1/overview`, `/api/v1/events`, `/api/v1/alerts`: bearer-protected read-only telemetry.
- `GET /api/v1/alerts/{id}/evidence`: verified event references for a rule match.
- `GET /api/v1/alerts/{id}/history`: operator-protected incident decision history.
- `POST /api/v1/alerts/{id}/transition`: operator-authenticated case transition. JSON fields: `expected_state`, `new_state`, `reason` (8–300 characters). Transitions: `open → investigating → resolved → investigating`; stale state conflicts return `409`. This changes *case status only*, never network controls.
- `GET /api/v1/audit/integrity`: local HMAC-chain integrity check.

Sensor signing algorithm: `HMAC_SHA256(sensor_secret, UTF8(sensor_id + "\\n" + unix_seconds + "\\n" + hex_32_nonce + "\\n" + SHA256_HEX(raw_body)))`, hex-encoded lowercase. Header names: `X-Sentinel-Sensor`, `X-Sentinel-Timestamp`, `X-Sentinel-Nonce`, `X-Sentinel-Signature`. Clock tolerance ±120 seconds. Payload limit 8 KiB. Sender identifiers are enrolled through private environment configuration in v0.2.

## Technology choices

- **Next.js / React / TypeScript**, bespoke editorial-dark design system and Lucide icons.
- **Python / FastAPI / Pydantic**, typed strict HTTP contracts.
- **SQLAlchemy + Alembic** for versioned SQLite/PostgreSQL schema changes; PostgreSQL concurrency integration tests in CI, but production HA is not qualified.
- **Read-only Linux SSH collector** with private cursor state and local HMAC-signed submission; no privileged firewall/network commands.
- **Pytest and GitHub Actions** for regression checks.
- No mandatory hosted AI service, payment API, commercial SOC vendor or paid account.

## Security and operational limits

**Do not connect unreviewed production devices or expose these endpoints publicly.** This proof of concept supports per-operator credentials with role-based permissions, but still permits one shared **legacy local-only** operator token when no individual enrollment mapping is configured; it has no MFA, general-purpose endpoint agent, network packet capture, advanced rate limiting, key lifecycle, robust multitenant isolation, independent tamper-proof audit storage, background queue or high-availability architecture. The audit integrity check also cross-checks stored incident decision payloads and current case status, but it remains vulnerable to full DB/key compromise and truncation. The open-core server currently assumes single-process local deployment. The state-based compare-and-set check prevents most stale updates but is not a substitute for versioned concurrency control under adversarial workloads. Schema migrations are now mandatory; the legacy SQLite upgrade path requires an offline backup and an explicit guarded baseline. Review [the threat model](docs/THREAT_MODEL.md) for additional gaps.

## Planned, not implemented

General network/endpoint sensor adapters and real agent enrollment; evidence graph and threat-intelligence enrichment; resource-bounded local AI analyst; tenant-aware OIDC/MFA access; approved defensive controls and audited rollback; production PostgreSQL operations, backup/restore verification and external audit anchoring; a consent-based offensive-security testing laboratory.

### Portfolio proof standard

Only claim features that pass reproducible tests and can be demonstrated from a clean environment. Track real-world metrics with methodology and dates. Avoid fake review scores, fabricated threat statistics and unverifiable performance claims.

## License

**No license has been selected yet.** The author retains rights until a license is chosen. Adding a permissive open-source license should be an explicit repository-owner decision.


## v0.7 — opt-in operator credential lifecycle

Versioned database-backed operator credentials support up to 90-day token expiry, immediate server-side revocation and atomic rotation. They are **not** remote IAM/SSO/MFA; use only with the localhost API. Static v0.4 tokens continue to work in the default mode. Database mode disables static fallback, requires an enrolled active administrator and uses an offline local CLI, never an HTTP credential-administration API.

After a private verified backup and Alembic upgrade, follow [local identity administration](docs/IDENTITY_AND_ACCESS.md) to enroll a new database admin and opt into `SENTINEL_AUTH_MODE=database`. Generated secret files must stay outside the source tree.
