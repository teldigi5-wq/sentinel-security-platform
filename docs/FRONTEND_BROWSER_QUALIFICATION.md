# Sentinel dashboard: Chromium smoke qualification (v0.31)

**Scope:** Real headless Chromium running the **Next.js production build**, using an
in-process, synthetic-only API bound to 127.0.0.1:8000. This is UI
qualification, not real-sensor or Linux-host certification, and is not a
substitute for manual accessibility review or a full WCAG/axe audit.

The browser test is a dependency-free Node.js script
(`frontend/scripts/browser-smoke.mjs`) using Chrome DevTools Protocol; it
installs no browser-testing package or unreviewed dependency tree. The
`frontend` GitHub CI job now runs it after `npm ci`, type-check and production
build, so the existing required `frontend` status check fails on a browser
regression. GitHub-hosted runners supply Chrome; no user machine is required.

## Checks

1. The anonymous login screen has an associated credential label and a masked input.
2. Invalid synthetic tokens are rejected and a visible alert appears.
3. A synthetic viewer signs in and receives sample metric/event data; the
   admin-only integrity navigation is absent and token is not persisted to
   browser local/session storage.
4. An event-navigation click displays the fixture; no viewer triage editor is shown.
5. The mobile (390px) drawer opens and closes, exposes an expanded state, and
   the page does not overflow horizontally.
6. Sign-out hides telemetry and clears the in-memory operator session.
7. An administrative fixture can open the integrity details tab.

All tokens, IPs, events and results are **synthetic test fixtures**. The
script launches a separate private Chromium profile and local Next.js server,
refuses to contact a configurable external API, and cleans up its processes.
It prints only pass/fail stage names; no real customer telemetry is loaded.

## Run

On an authorized development machine with Node 22, a standard browser
executable installed and the reviewed frontend dependencies available:

```sh
cd frontend
node scripts/verify-lockfile.mjs
npm ci --no-audit --no-fund
npm run typecheck
npm run build
node scripts/browser-smoke.mjs
```

`node scripts/browser-smoke.mjs --self-test` tests only the browser protocol
harness, not the production Next.js application. Browser policy in some managed
containers blocks all navigation; full browser qualification must use the
actual green GitHub CI run on its published commit. A headless browser test
with synthetic API is not an actual end-to-end test of backend authorization.

## Limitations and follow-ups

- Manual keyboard-only use and screen-reader testing remain outstanding.
- Add an independent automated accessibility audit (e.g., axe) only after its
  new dependency and lockfile have been reviewed.
- Verify real backend CORS, HTTP headers, performance and operator workflows
  separately in an authorized environment, not through these synthetic stubs.
- No Linux-host reboot, journald recovery or live sensor reading occurs here.