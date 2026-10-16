# Integrity scan admission control (v0.27)

The viewer-scoped `/api/v1/audit/status` and admin-only `/api/v1/audit/integrity` endpoints inspect the **entire audit history** on each request. This work grows with evidence volume. A valid viewer credential must not be able to queue unlimited concurrent database scans.

Sentinel now applies one shared, fail-closed **per-process** admission gate *after* operator authentication:

- Only **one** full evidence verification executes at a time per application instance. Overlapping requests get HTTP 429 with `Retry-After: 2`.
- Only **12 scans may begin per rolling 60-second window** per application instance. Extra requests get HTTP 429 with `Retry-After: 60`. Even failed scans consume budget.
- Both routes share the budget; invalid credentials still receive HTTP 401. Other API endpoints remain accessible.
- Every admitted scan still performs a fresh database verification; no caching, bypass or weakening of HMAC checks. Database failures remain HTTP 503.
- No keys, tokens, evidence records or IP addresses appear in the admission error messages.

**Important limitations:** This is not a distributed rate limiter. Each Uvicorn worker and each deployed host has its own budget. It does not stop an attacker with OS/database privileges or defend against network-level request floods. Use trusted loopback-only network binding, strong revocable viewer credentials, process resource limits, and a dedicated firewall/reverse-proxy policy when appropriate. Schedule a legitimate monitor conservatively (for example, every five minutes). Verified evidence state is still a point-in-time observation, not real-host certification.

Tests: `cd backend && python -m pytest tests/test_integrity_scan_guard.py` followed by full backend and GitHub CI. No migrations or production host changes are required.
