# API startup evidence integrity gate (v0.23)

**Scope:** Backend initialization only, before accepting operator or sensor requests. A valid migrated database is required. Startup now verifies the sequential audit HMAC, case-state decisions, and sealed v0.22 normalized event fields in one consistent snapshot. It refuses startup when they disagree; it **does not** repair evidence or bypass the failure.

A startup failure means a human operator should stop the service, preserve the original DB and key securely, investigate unauthorized changes, and use the existing offline verified-backup recovery procedure **only if appropriate**. Do not overwrite or delete the potentially compromised original data. Never put secrets or raw event payloads in GitHub issue logs.

**Historical limitations:** pre-v0.22 events carry only ID-level audit authentication; startup accepts them for backward compatibility, but payload content remains unverified. The check occurs once at application startup, not continuously. If the database changes after startup, only explicitly invoked later integrity checks can detect that change. A compromised audit HMAC key or manipulated sensor input cannot be ruled out. The audit chain is not an externally immutable record.

**Concurrency:** PostgreSQL startup verification uses a repeatable-read transaction so the multi-table inspection is from one database snapshot. SQLite uses its transactional snapshot. The preflight scans audit records and event rows, so startup time grows with database size; benchmark on actual target hosts before production approval. Avoid claiming continuous evidence integrity from a successful startup.

**Release acceptance:** The five new tests cover a valid restart, event tampering, audit-record tampering, case-decision tampering, and historical data compatibility. Independent GitHub PostgreSQL and integration CI are required. A real Linux-host service restart and resource budget measurement remain pending. This change has no migration, network egress, destructive cleanup or new paid dependency.
