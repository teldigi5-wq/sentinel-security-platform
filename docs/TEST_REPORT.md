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

**Not verified:** cross-browser accessibility, live browser UI, production PostgreSQL behavior, deployment, actual endpoint sensor integrations, performance at scale, network intrusion detection/prevention, vulnerability exploitation testing, AI model reasoning, recovery/rollbacks.

**Local environment limit:** the original workspace could not resolve `registry.npmjs.org` (`EAI_AGAIN`); it has not run a local Next.js build or real-browser accessibility evaluation. GitHub Actions has since independently installed frontend dependencies, passed TypeScript checking and built the production frontend successfully.

**Remote CI evidence (2026-10-15):** [Sentinel quality gates, run #38770175539](https://github.com/teldigi5-wq/sentinel-security-platform/actions/runs/38770175539), on commit [`1b21a599`](https://github.com/teldigi5-wq/sentinel-security-platform/commit/1b21a599c3a5b376d325ca1d67bd30735495eb4b). Backend job: **success**; frontend dependency installation, TypeScript check and Next.js production compilation: **success**. This verifies the initial GitHub build only, not production security or real-world network protection.
