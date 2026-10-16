# Sentinel v0.1 — verification record

**Date:** 2026-10-15 (workspace UTC clock may differ).

**Environment:** Python 3.13.5, FastAPI 0.128.2, SQLAlchemy 2.0.50, Pydantic 2.13.5, pytest (installed in working environment). No cloud services required.

**Command:** `cd backend && PYTHONPATH=. pytest -q`

**Observed result:** `13 passed` (all listed local backend tests passed).

Verified backend behavior:

- API health and mandatory operator authentication.
- Five signed login failure events create a correlated alert and five evidence links.
- A reported malware indicator creates a high-severity alert; no malware execution.
- Invalid HMAC, expired signatures, replayed nonces and unknown sensor IDs rejected.
- Oversized JSON, malformed input, mismatched categories and stale observed events rejected.
- Separate source IPs do not accidentally share authentication-failure thresholds.
- A twelve-event network-denied burst generates an investigation alert.
- Sensor keys alone cannot access the operator API.
- Audit-chain editing causes an integrity verification failure.
- Restricted browser CORS origin and explicit UTC timestamp serialization verified.

**Not verified:** Next.js frontend compilation, cross-browser accessibility, live browser UI, npm dependency install, production PostgreSQL behavior, CI on GitHub, deployment, actual endpoint sensor integrations, performance at scale, network intrusion detection/prevention, vulnerability exploitation testing, AI model reasoning, recovery/rollbacks.

**Blocker:** frontend npm dependencies could not be installed; the environment could not resolve `registry.npmjs.org` (`EAI_AGAIN`). The local Next.js source requires `npm install`, `npm run typecheck`, `npm run build`, and real browser inspection when package registry access is available. No fabricated build or CI pass is claimed.

The test count and result are local observations only. GitHub CI is defined but has not been executed in a remote repository.


## Sentinel v0.2 — local triage verification

- Local Python 3.13, pytest 9.0.2, FastAPI 0.128.2 and SQLAlchemy 2.0.50: **18 backend tests passed**, including the original 13 baseline tests.
- Added authenticated incident state changes, rejected illegal transitions, stale update conflicts, bounded JSON body, reason validation, CORS checks, missing-record behavior, history reads, HMAC integrity and decision tampering detection.
- TypeScript/TSX syntax was parsed using local TypeScript 5.8.3 without syntax diagnostics. **Full Next.js build and browser end-to-end verification must run on GitHub CI before claiming success.**
- No penetration test, real sensor integration, advanced rate limiting, database migration rehearsal, deployment, or production-ready multi-operator authentication is claimed.


## Sentinel v0.3 — real Linux SSH collector verification

**Date:** 2026-10-16. **Environment:** Python 3.13.5, pytest 9.0.2, FastAPI 0.128.2, SQLAlchemy 2.0.50. **Command:** `cd backend && python -m pytest -q`.

**Observed local result: 31 passed.** The 13 new collector tests include strict IP normalization, payload minimization, cursor restart, append handling, failed-transport retry, incomplete line retention, log rotation/truncation, private file permissions, symlink refusal, corrupt cursor rejection, oversized line safety, loopback-only transport and fixture-to-Sentinel signed ingestion to deterministic alert and audit validation. Truncation now rotates a state generation so reused offsets do not collide with prior event nonces.

**CI checks added:** bytecode compilation and `pip check` before regression suite, least-privilege job permissions and finite job timeouts. These are defined as required repository checks for PR review; actual remote success must be confirmed from the specific GitHub run before claiming it.

**Not verified:** live distribution-specific logs, runtime privileges on deployment hosts, Windows support for this Linux-only sensor, real network enforcement, PostgreSQL migration, dependency vulnerability scan, large-scale throughput, live frontend cross-browser usage, or penetration-test qualification. Previous v0.2 CI claims are supported separately by that PR's recorded workflow run.
