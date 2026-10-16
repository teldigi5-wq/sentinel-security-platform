# Sentinel v0.33 — keyboard access and hostile telemetry regression

This is an **automated Chromium regression**, not a full WCAG accessibility
audit, independent security assessment, deployed-host test, or penetration test.

## What changed

- On mobile, opening the navigation drawer by keyboard focuses its first
  navigation control.
- Tab and Shift+Tab wrap between navigation controls; Escape closes the drawer
  and returns keyboard focus to the toggle. Closing by selecting navigation or
  clicking outside also restores focus.
- Active navigation uses `aria-current`; the toggle maintains `aria-expanded`
  and `aria-controls`; the alert-table action header is labelled.
- Clearing or revoking a session resets the navigation state.
- A synthetic API fixture includes a malicious-looking HTML image tag in an
  alert title, alert explanation and event source value. Chromium must render
  the exact literal text, create no injected DOM node and execute no event
  handler. React text binding is the actual escaping boundary.

## What the tests mean

The mock API browser test checks intentionally hostile display values and
keyboard behavior. The separate real FastAPI+Next.js test still uses signed,
seeded synthetic events to cover actual API authorization and evidence links.
Both are run by the existing required GitHub `frontend` job; no new dependencies,
paid infrastructure, or production deployment were added.

The current CSP retains inline-script compatibility for Next.js. These
regressions are **not** proof against all XSS attacks, WCAG compliance, complete
keyboard usability, assistive-technology behavior, or real Linux-host recovery.

## Reproduce

From a clean checkout with the declared and pinned CI dependencies:

```sh
cd frontend
npm ci --no-audit --no-fund
npm run typecheck
npm run build
node scripts/browser-smoke.mjs
node scripts/browser-real-backend.mjs
```

The second command requires a local Python backend with reviewed test
constraints and starts a private synthetic-seeded FastAPI server on loopback.
Never use production tokens or real event logs in these tests.
