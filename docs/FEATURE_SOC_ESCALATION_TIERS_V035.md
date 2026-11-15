# L1 / L2 / L3 alert-triage escalation tiers (v0.35)

Date: 2026-11-15 · Branch: `feature/sensor-ingest-rate-bound-v034-20261114` · Base: `test/keyboard-and-untrusted-ui-v033-20261016`

## Why
Requested directly: bring a standard security-operations-center (SOC) tiering
model into Sentinel's alert triage, so a high-severity finding cannot be
closed solo by the same tier that closes routine alerts.

## Design decision worth flagging explicitly
The obvious reading of "L1/L2/L3" would give L1 (viewer) some write access
(e.g. "acknowledge"). **This implementation does not do that.** Sentinel
already has a tested, named invariant — `test_viewer_is_read_only_and_cannot_access_audit`
in `backend/tests/test_operator_rbac.py` — that a viewer must never be able to
modify an alert's state. Loosening that is a real policy reversal, not a
refactor, and isn't something to ship as a side effect of an unrelated
feature. So L1 here is read-only and exists only for naming/reporting
(`GET /api/v1/session` reports `"tier": "L1"`); the enforced, behavior-changing
part of this feature is entirely the **L2 → L3 escalation on high-severity
close**. If genuine L1 write access (e.g., "acknowledge only") is wanted,
that's a separate, explicit decision for the project owner to make — flagging
it here rather than deciding it unilaterally.

## Change
- `backend/sentinel/escalation.py` (new): role→tier map, per-transition and
  per-severity tier requirements, fail-closed default (unknown severity → L3).
- `backend/sentinel/app.py`:
  - `POST /api/v1/alerts/{id}/transition` now reads the alert's severity and
    rejects (403, naming the required tier) a close attempt below it, instead
    of gating the whole endpoint on a single "analyst-or-admin" role check.
  - `GET /api/v1/session` reports `tier` and a `close_high_severity` capability.
  - `GET /api/v1/alerts` reports each alert's `close_tier` ("L2"/"L3").
- `frontend/app/page.tsx`: shows each alert's required close tier in the table,
  and surfaces the backend's escalation message on a blocked close instead of
  a bare "HTTP 403". **Not type-checked locally** (no `node_modules` / network
  access in this environment) — CI is the first real compile/test evidence.
- `backend/tests/test_alert_escalation_tiers.py` (new): tier table, L2 closes
  medium alone, L2 blocked on high with no state/audit side-effect, L3 then
  closes it, viewer still fully blocked at every severity, `/alerts` and
  `/session` report the new fields correctly.
- No database migration: the required tier is computed from the alert's
  existing `severity` column at request time, not stored.

## What this does NOT do
- Does not add new roles or touch `credential_lifecycle.py`'s role set or its
  single-admin invariant.
- Does not notify, page, or route an escalated alert to anyone — it only
  blocks the close and names the tier required.
- Does not touch ingestion, detection, or the v0.34 rate-limit/systemd work on
  this same branch.

## Evidence status
- Planned: yes · Coded: yes
- Locally tested: **NOT RUN** (no package/network access in the authoring
  environment); new tests were checked by manual trace against
  `detection.py`'s actual severity thresholds, not executed
- CI on exact SHA `ab4733c`: 14/14 checks green (push + PR, 7 jobs each), including the frontend build, which is also the first real compile check on the hand-written TSX edit.
- Merged / deployed / owner accepted: **no**

## Recommended follow-up for the owner
1. Confirm the design decision above (L1 stays read-only) matches intent, or
   explicitly request L1 write access as a separate, reviewed change.
2. Decide whether `low`-severity alerts should also require L3 for some rule
   types later, or stay at L2 as now.
3. If real SOC hand-off (notification/paging/SLA) is wanted, scope that as its
   own feature — this PR is authorization only.
