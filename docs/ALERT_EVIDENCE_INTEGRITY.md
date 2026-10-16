# Alert and evidence-link integrity (v0.26)

**Status:** automated development qualification only. This is not host certification, external immutability or legal evidence custody.

## Security gap addressed

Earlier audit records authenticated the alert ID, but not the stored alert details or the link between an alert and its supporting security events. A database writer could change alert severity, title, source, or associated evidence without altering the old audit chain.

## New verified behavior

- `alert.created` now records `alert:v1:<alert-id>:<sha256>`, binding persisted immutable alert fields (including rule, fingerprint, severity, title, explanation, source, asset and creation time) to the authenticated audit chain.
- Every new alert-to-event association records `alert.evidence.linked` with `link:v1:<alert-id>:<event-id>` in the audit chain, including new links to an existing alert.
- At API startup and at the authenticated runtime integrity endpoint, compare current alert rows and evidence-link rows with their authenticated audit entries; verify evidence counts against actual rows and incident state against signed analyst decisions.
- Offline backups and replay-nonce maintenance reject newly detectable tampering.
- No database schema changes, deletions, remote network scanning, or mandatory paid services.

## Historical and threat-model limitations

Pre-v0.26 alerts and evidence links are **not retroactively authenticated**. The admin endpoint reports `legacy_unanchored_alert_records`, and the viewer endpoint responds `partial_legacy` when historical alert or link assurance remains incomplete.

A sensor lying at collection time, compromise of the signing key, full rollback or replacement of a database and its key, or a malicious privileged host operator remains outside the guarantee. Audit results are only as independent and trustworthy as the local key and storage.

For larger datasets, full integrity scans scale with the historical evidence volume; plan bounded/ incremental verification separately.

## Development checks

```bash
cd backend
python -m pytest -q tests/test_alert_evidence_integrity.py
python -m pytest -q
```

PostgreSQL integration and complete CI qualification must pass independently before this draft is eligible for review.
