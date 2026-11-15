# Responsible security development

This is an **experimental pre-production security platform**. Do not expose its operator API or UI to the public internet or rely on it as your sole network defense. Do not forward real sensitive production telemetry until data retention, role-based authorization, proper TLS/mTLS, backups and incident handling are implemented.

## Report vulnerabilities

Use private GitHub vulnerability reporting when enabled on the repository. Never post credentials or sensitive exploit details in a public issue. Maintainers should triage privately and publish tested fixes and security advisories after remediation.

## Development invariants

- No embedded secrets, public API keys or production event datasets.
- No exploit/retaliation automation, malware redistribution, or arbitrary execution through model output.
- No silent write access to protected production systems.
- No assertion of independent forensic immutability from a local HMAC chain.
- Every action that changes network policy will require explicit approved target scope, expiry and rollback in a future controlled release.

## Sensor ingest rate bound (v0.34)

Signed sensor routes (`/api/v1/events`, `/api/v1/sensors/heartbeat`) share an
in-process per-sensor quota (default 300 requests / 60 s, at most 512 tracked
sensors). Requests are counted only after HMAC verification **and** after the
nonce is confirmed unseen, so neither forged nor replayed traffic can exhaust a
genuine sensor's quota. Exceeding it returns HTTP 429 with `Retry-After`.

Limitations: counters are per worker process and reset on restart; this is not a
distributed quota. Multi-worker or multi-instance deployments still need an
ingress rate limiter. If concurrent copies of one signed request race past the
stored-nonce pre-check, the copy rejected by the database unique constraint has
its quota unit refunded, so concurrent replays cannot drain quota either. The
default 300/60 s budget, 512-identity bound (least-recently-active eviction,
reachable only by keyed sensors) and fixed `Retry-After` (window length, an
upper bound rather than an exact reset time) are local single-process choices.

## Alert triage escalation tiers (v0.35)

Alert triage is gated by an L1/L2/L3 tier derived from the operator's existing
role (`viewer`→L1, `analyst`→L2, `admin`→L3), enforced in
`backend/sentinel/escalation.py`:

- **L1 (viewer)** is unchanged: read-only. It cannot acknowledge, close, or
  reopen an alert — this was an existing invariant and this feature does not
  loosen it.
- **L2 (analyst)** can acknowledge an alert and close it when its severity is
  `low` or `medium`.
- **L3 (admin)** is additionally required to close a `high`-severity alert, or
  any alert of a severity this table does not recognize (fail closed to the
  highest tier, not the lowest). An L2 operator who reaches that point gets a
  403 naming the required tier; Sentinel does not page, notify, or otherwise
  perform the hand-off itself.

Limitations: this is an authorization rule on Sentinel's own triage endpoint,
not a SOC ticketing/escalation system. It does not track who an alert was
escalated to, notify anyone, or enforce an SLA on how quickly L3 responds.
