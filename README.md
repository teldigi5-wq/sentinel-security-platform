# SENTINEL — Evidence-Driven Security Operations

**Standalone · Local-first · Zero mandatory paid subscriptions · Pre-production v0.1.0**

> **Implementation status:** a functioning local security event ingestion and detection core, operator dashboard source, and automated backend tests. **Not yet a complete SOC, EDR, antivirus, firewall, commercial security replacement, attacker-tracing tool or offensive platform.** No claim of enterprise certification or live network protection is made.

SENTINEL explores how security telemetry, deterministic rules, traceable incident evidence and constrained AI-assisted investigation can evolve into a verifiable defense platform. This initial release deliberately has **no destructive, retaliatory or live network enforcement features**.

## What is actually implemented

| Module | Status | Evidence |
| --- | --- | --- |
| HMAC-authenticated sensor ingestion | Implemented | `backend/sentinel/app.py`, signed requests and tests |
| Replay resistance + size/schema limits | Implemented | `backend/tests/test_api.py` |
| Failed-login burst detection | Implemented | `backend/sentinel/detection.py` |
| Network-denied burst, malware indicator and denied elevation rules | Implemented | Deterministic rules and tests |
| Alert/evidence correlation | Implemented | `/api/v1/alerts/{id}/evidence` |
| HMAC-linked local audit and integrity checking | Implemented with documented limitations | `backend/sentinel/audit.py` |
| Authenticated read-only APIs | Implemented | `/api/v1/overview`, `/alerts`, `/events` |
| Premium operator dashboard | Source provided; frontend build **not locally verified** | `frontend/app` |
| Live Wazuh/Suricata/endpoint adapters | **Not implemented** | Planned |
| Automated blocking, network protection or honeypots | **Not implemented** | Planned with approval gates |
| AI-powered investigation and threat graph | **Not implemented** | Planned |

## Architecture

```text
Lab event emitter (future: approved endpoints / sensors)
   │ signed timestamp + unique nonce + payload HMAC
   ▼
FastAPI signed event ingestion ──► schema validation and bounded payloads
   │
   ▼
SQLite (default) / PostgreSQL (optional future target)
   │
   ├── Security events
   ├── Deterministic detection → Alerts → Evidence links
   └── HMAC-chained local audit records
   │
   ▼
Authenticated read-only APIs ◄── Next.js operator dashboard
```

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

The operator token stays in tab memory and must be re-entered after reload. The web app fetches observed data; it does not manufacture alerts or inflate metrics.

### Windows PowerShell alternative

Create the venv with `py -m venv .venv` and activate with `.venv\Scripts\Activate.ps1`. Set environment variables using `$env:SENTINEL_OPERATOR_TOKEN=...`, `$env:SENTINEL_AUDIT_KEY=...`, `$env:SENTINEL_SENSOR_KEYS='{"lab-sensor-1":"..."}'` in the backend terminal before running `uvicorn`. Repeat the sensor variable in the demo sender terminal. `.env` is not auto-loaded by Python.

## Backend test suite

```bash
cd backend
python -m pip install -e '.[test]'
python -m pytest -q
```

Tests use isolated temporary SQLite databases and random event nonces. They require no cloud credentials. CI runs backend tests and attempts frontend type checks and build separately.

## Operator API (localhost only)

- `GET /api/v1/health`: non-sensitive health status.
- `POST /api/v1/events`: HMAC-signed sensor ingestion, HTTP 202.
- `GET /api/v1/overview`, `/api/v1/events`, `/api/v1/alerts`: bearer-protected read-only telemetry.
- `GET /api/v1/alerts/{id}/evidence`: verified event references for a rule match.
- `GET /api/v1/audit/integrity`: local HMAC-chain integrity check.

Sensor signing algorithm: `HMAC_SHA256(sensor_secret, UTF8(sensor_id + "\\n" + unix_seconds + "\\n" + hex_32_nonce + "\\n" + SHA256_HEX(raw_body)))`, hex-encoded lowercase. Header names: `X-Sentinel-Sensor`, `X-Sentinel-Timestamp`, `X-Sentinel-Nonce`, `X-Sentinel-Signature`. Clock tolerance ±120 seconds. Payload limit 8 KiB. Sender identifiers are enrolled through private environment configuration in v0.1.

## Technology choices

- **Next.js / React / TypeScript**, bespoke editorial-dark design system and Lucide icons.
- **Python / FastAPI / Pydantic**, typed strict HTTP contracts.
- **SQLAlchemy + SQLite for local operation**; PostgreSQL driver supported but production concurrency/migrations not yet qualified.
- **Pytest and GitHub Actions** for regression checks.
- No mandatory hosted AI service, payment API, commercial SOC vendor or paid account.

## Security and operational limits

**Do not connect unreviewed production devices or expose these endpoints publicly.** This proof of concept has no MFA, real endpoint agent, network packet capture, advanced rate limiting, key lifecycle, robust multitenant isolation, independent tamper-proof audit storage, background queue or high-availability architecture. The audit chain is not proof against full DB/key compromise. The open-core server currently assumes single-process local deployment. Review [the threat model](docs/THREAT_MODEL.md) for additional gaps.

## Planned, not implemented

Network sensor adapters and real agent enrollment; evidence graph and threat-intelligence enrichment; resource-bounded local AI analyst; tenant-aware OIDC/MFA access; approved defensive controls and audited rollback; robust storage and migration strategies; a consent-based offensive-security testing laboratory.

### Portfolio proof standard

Only claim features that pass reproducible tests and can be demonstrated from a clean environment. Track real-world metrics with methodology and dates. Avoid fake review scores, fabricated threat statistics and unverifiable performance claims.

## License

**No license has been selected yet.** The author retains rights until a license is chosen. Adding a permissive open-source license should be an explicit repository-owner decision.
