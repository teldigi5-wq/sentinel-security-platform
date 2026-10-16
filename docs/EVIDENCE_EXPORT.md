# Sentinel v0.17 — Sealed event-evidence export (development)

The **offline-only** event exporter creates a private, HMAC-authenticated copy of eligible normalized event rows and linked alert IDs from an independently verified, consistent SQLite snapshot. **It never deletes or alters the source database**, does not archive complete cases (including all incident decisions), does not verify original sensor-row immutability, and is **not** an externally immutable evidence vault or a production retention-policy implementation.

## Operator procedure

Run while authorized as the local database custodian. Store archives outside web-served directories, on private, access-controlled storage. Source IPs may constitute personal information; handle backups/exports as sensitive security data. The output directory must not already exist, and its parent must not be group/world writable.

```bash
cd backend
export SENTINEL_AUDIT_KEY='<existing-secure-secret-from-your-secret-manager>'
python -m scripts.export_event_evidence export /private/sentinel.db /private/evidence-batch-001 --days 30 --max-events 1000
python -m scripts.export_event_evidence verify /private/evidence-batch-001
```

Never paste the actual audit secret into shell history. Prefer a protected environment injection mechanism and scrub the session afterwards. The placeholder above is **not** a usable key.

An export includes events **received** before the UTC cutoff, preventing a just-received delayed event from being automatically treated as old. A selection larger than the explicit event bound is refused instead of silently truncated. `events.jsonl` and `manifest.json` are created as owner-only (`0600`) files in a newly created owner-only (`0700`) directory. The manifest signs the digest, counts, cutoff and snapshot audit-head summary using a domain-separated HMAC based on the audit key. Verification requires the same key, but not the source database.

## Threat and operational limits

- The original database, security events, alerts, alert-evidence links and audit trail **remain untouched**. An export is a **copy** and does not reclaim primary-database storage.
- Hash/HMAC signatures detect later modification without the audit key. A compromised audit key can forge a new bundle. No third-party timestamp or independently anchored log exists.
- A valid audit chain alone does not prove the unmodified contents of every original `security_events` row; the bundle attests to a verified database **snapshot at export**, not end-to-end endpoint provenance.
- The event archive contains link identifiers, not the complete alert record, operator decisions, or case narrative. Keep the original database and signed recovery backups.
- SQLite point-in-time snapshot consistency is tested in an isolated environment; production host crash consistency, external backup durability, access controls and off-host restore drills remain unqualified.
- Export files hold sensitive IP addresses and asset identifiers; use off-host encryption and access control at the storage layer. Do not upload real exports as public GitHub artifacts.
- Do not create automated event deletion until there is a separately reviewed, tested archive index, restoration process, and evidence continuity model.
