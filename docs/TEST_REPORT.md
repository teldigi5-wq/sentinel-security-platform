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
