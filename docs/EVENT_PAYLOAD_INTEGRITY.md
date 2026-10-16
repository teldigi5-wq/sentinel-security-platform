# Event payload evidence anchoring — v0.22

**Status:** automated-development qualification; not a complete forensic chain of custody or external immutable archive.

## Problem verified by regression test

Before v0.22, the HMAC audit `event.ingested` entry referenced only the normalized event ID. A database writer without the HMAC audit key could change the event's IP, action, asset, category, timestamps or sensor while the audit chain itself still verified. That was misleading evidence integrity.

## What this change does

New signed ingestions append `event:v1:<event-uuid>:<sha256>` as the resource of `event.ingested`. The SHA-256 digest covers a versioned, unambiguous JSON array of the **persisted** event's ID, sensor, asset, category, action, nullable source IP, normalized UTC event time and receipt time. This digest is itself authenticated through the existing serialized HMAC audit chain and transactional writer lock. The 110-character resource fits the existing 140-character column; **no schema migration is required**.

`verify_event_evidence()` cross-checks all event-ingestion audit records against the stored event table: one unique audit resource per row, authenticated-sensor actor for new v1 entries, and matching field digest. A missing, duplicate or modified event returns a failed integrity status, even when the HMAC link sequence is otherwise intact. The admin-only audit API exposes `event_payload_assurance` and `legacy_unanchored_events` so operators can distinguish unanchored historical data from newly sealed evidence. Safe SQLite backup/restore and nonce maintenance now refuse databases with detectable v1 event-payload alterations. Non-destructive export inherits the backup qualification.

## Existing evidence and compatibility

**Do not rewrite or retroactively re-sign production history.** Older `event.ingested` resources contain only the original ID and do not authenticate event contents. The verifier will check that the referenced row exists, but reports `event_payload_assurance: partial_legacy` and a nonzero `legacy_unanchored_events` count. `valid: true` then means the supported **audit-chain and row-reference checks** passed, **not** that historical event fields are authentic. A missing or duplicate legacy event is rejected. Consumers must not collapse `partial_legacy` into full evidence assurance.

The legacy format remains compatible with legitimate previous migrations and backups; no destructive backfill or automatic archival is performed. Any evidence copied from an old snapshot preserves its original limited trust level.

## Boundaries and known gaps

- The same local HMAC secret authenticates the chain. Someone who steals the audit key and gains database write access could fabricate a matching chain; there is **no external immutable anchor**.
- HMAC authenticates **storage consistency**, not whether a compromised sensor originally reported truthful information.
- New event field anchors do **not** authenticate mutable alert descriptions, alert evidence link contents, or sensor-health rows. Incident decisions have a separate existing cross-check.
- Full-table integrity checks are O(N) in database size; large installations need bounded operational verification and external archival before production scale.
- SQLite backup/restore, Linux host deployment, browser accessibility, real-world rule quality and threat containment remain separately qualified capabilities. This release performs no enforcement.

## Verification

From `backend/` with declared development/test packages installed:

```sh
python -m pytest -q tests/test_event_payload_integrity.py tests/test_evidence_export.py tests/test_release_candidate.py
python -m pytest -q
```

Regression cases show that a changed event action/source IP passes the *old* HMAC-chain-only validation but fails v1 evidence verification; backup/maintenance refuse altered records. Historical fixture tests explicitly reseal only **synthetic test data** with a known test key. Re-signing real production evidence to conceal a mutation is forbidden.
