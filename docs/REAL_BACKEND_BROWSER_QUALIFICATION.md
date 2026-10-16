# Real FastAPI and Next.js browser qualification (v0.32)

Status: **temporary CI integration test with synthetic events**, not host certification,
continuous monitoring, production deployment, or a complete WCAG accessibility audit.

The existing `frontend/scripts/browser-smoke.mjs` still uses a synthetic Node
HTTP API. The additional `frontend/scripts/browser-real-backend.mjs` instead:

1. Creates a private, disposable directory and uses the real Alembic migration
   chain to initialize a SQLite database.
2. Generates temporary, high-entropy viewer/admin tokens, an audit key, an
   enrolled sensor signing key and fixture-only Test-Net IP address.
3. Calls actual FastAPI signed-ingestion endpoints five times plus a signed
   heartbeat. The detection engine must produce one evidence-linked alert.
4. Asserts real API permission boundaries (unauthorized 401, viewer forbidden
   on the admin integrity endpoint, admin verified audit state).
5. Starts the real uvicorn application **only on 127.0.0.1:8000** and starts
   the production-built Next.js dashboard **only on 127.0.0.1:3100**.
6. Drives Chromium using Chrome DevTools Protocol: wrong credentials rejected;
   viewer session shows five events and a real alert with five evidence links;
   role-limited controls, mobile viewport, sign-out, and admin-only integrity tab.
7. Tears down both processes and deletes the private temporary directory.

Run in an isolated runner after `pip install -c backend/constraints/py312-linux-ci.txt
-e ./backend[test]`, `npm ci`, and `npm run build`:

```sh
cd frontend
node scripts/browser-real-backend.mjs
```

Secrets are generated per run and held only in an owner-private temporary
fixture file; **never upload that file or reuse it with a production backend**.
GitHub Actions retains no database, tokens, raw events or screenshots. Browser
stdout prints assertion names only. The test does not require an actual Linux
SSH log, reboot, systemd service or production credentials.

This qualifies the real UI/API contract for one synthetic localhost dataset;
it does not prove accessibility compliance, arbitrary user data correctness,
endpoint protection or real host availability.