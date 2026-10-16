# v0.16 — Replay-nonce retention guard

**Scope:** local, opt-in SQLite replay-nonce maintenance. **Not** security-event, alert, audit, or decision retention. Historical evidence remains untouched. No network action or scheduling is enabled.

The sensor signature timestamp must fall within ±120 seconds, so a previously captured request outside this window cannot be accepted regardless of its nonce. The default seven-day retention interval is intentionally far longer than that validity window. Do not reduce this below one day or use this utility to cover clock synchronization failures. Nonce cleanup does **not** rotate stolen signing keys or protect compromised hosts.

## Operator workflow

1. Stop or quiesce ingestion if possible. Keep `SENTINEL_AUDIT_KEY` in the environment without placing it in shell arguments.
2. From `backend/`, preview: `python -m scripts.retention_maintenance /private/sentinel.db --days 7`. Preview checks current schema and audit/decision integrity and lists only counts.
3. Apply with a **new**, private backup directory: `python -m scripts.retention_maintenance /private/sentinel.db --days 7 --apply --backup-dir /private/backup-before-retention-001`. The backup is created and its audit integrity verified **before** any deletion. Existing backup destinations cannot be overwritten.
4. Save the JSON counts with your operational evidence separately. Verify the new backup using `python -m scripts.sqlite_recovery verify /private/backup-before-retention-001` and confirm `/api/v1/audit/integrity` after restarting the API.

Only `sensor_nonces` rows older than the cutoff are removed. A successful change adds an `replay-nonces.pruned` HMAC audit entry. The operation refuses an unsupported database schema, incorrect audit key, case-decision corruption, a missing/unwritable backup destination or audit-head movement since the snapshot.

## Explicit limitations

- **SQLite only.** This is not a PostgreSQL maintenance procedure and must not be pointed at other backends.
- Backups are local and unencrypted; use access controls, secure off-host copying and recovery drills separately.
- The HMAC audit chain is not externally anchored or immutable. Whole-database rollback/deletion by a sufficiently privileged attacker remains possible.
- A concurrent non-audit write outside Sentinel's transaction model cannot be detected by audit-head comparison. Stop ingestion for a consistent maintenance window.
- Preview is a point-in-time estimate; apply can remove fewer or more rows if time or database state changes.
- No deletion of `security_events`, `alert_evidence`, `alerts`, `alert_decisions`, or `audit_records` is permitted: evidence-preserving archival must be designed and independently qualified before any event retention automation.
- The utility has no scheduler, HTTP endpoint, alert notification, real-host performance benchmark or production sign-off.
