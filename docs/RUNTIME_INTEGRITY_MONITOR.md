# Runtime evidence-integrity monitoring (v0.24)

**Scope:** read-only verification of Sentinel's local security-event and audit-database consistency **while the server is running**. It is not continuous host protection, real-time threat blocking, an immutable evidence store, or certification of a Linux host.

## Purpose and threat model

The startup gate refuses an already-compromised evidence database. Subsequent manual verification is available to administrators, but a long-lived service needs a scheduled, lower-privilege **signal** without distributing an admin token or the audit-HMAC key. The new `GET /api/v1/audit/status` route accepts an authenticated viewer, and reports *only* consistency state, a boolean, and whether any events exist. It does not return event records, user identities, incident identifiers, log lines, local paths, or cryptographic keys. The original detailed `/api/v1/audit/integrity` remains admin-only.

The request obtains a **fresh database transaction**; PostgreSQL uses repeatable-read isolation to prevent mismatched audit snapshots during concurrent ingestion. SQLite uses a consistent read transaction. A DB error yields HTTP 503, **not** an affirmative state. The operation checks HMAC audit entries, event-row anchors, and case-decision history, so verification cost grows with accumulated evidence; do **not** run it per ingestion event or at excessively high frequency.

## Read-only localhost CLI

Provision a **viewer** operator credential using the existing offline credential workflow. Store its token as a private, user-owned regular file (0600), and run the probe under the same unprivileged account, with the Sentinel backend bound to localhost.

From `backend/`:

```sh
python -m scripts.check_audit_integrity --token-file /absolute/private/path/viewer.token --port 8000 --json
```

The tool connects only to `127.0.0.1` using the fixed `/api/v1/audit/status` endpoint. It does not use a proxy, redirects, DNS, or configurable remote URL. It reuses the existing secure private-token-file loader; no token is printed to logs or placed in a process argument. A run must be independently scheduled if desired (e.g. via a local least-privilege user systemd timer). There is **no automatic task installation**, host system modification, or remote reporting.

| Exit code | Meaning | Automation handling |
|---|---|---|
| `0` | Anchored event evidence, valid chain and case history, at least one event | Successful local evidence consistency check only |
| `2` | Integrity failure, pre-v0.22 partially anchored records, or no events | Attention required; do not certify |
| `1` | Unavailable API, denied credential, malformed/oversized response, timeout or network failure | Unknown; alert rather than assume healthy |

Sample (illustrative, not a live-host result):

```json
{"evidence_state":"partial_legacy","has_events":true,"host_certified":false,"integrity_clear":false}
```

### Incident response

If integrity is failed, stop trusting the affected evidence for operational decisions, preserve a non-mutating snapshot, and investigate the host, database and audit key. Do not rewrite or delete evidence to make the check green. The API deliberately does **not** stop itself when a later check fails, because such remediation requires a documented operational incident workflow; the monitoring tool merely reports the failure. If the response is unknown, check local network, service and viewer credential status while treating evidence assurance as unavailable.

### Limits

- A process with both database and audit-key access can forge records; the chain is not externally immutable.
- Legacy records have an authenticated ID-only audit reference, not a payload hash; this always produces a degraded signal.
- An empty, otherwise valid database does not prove successful ingestion.
- The query provides a point-in-time consistency assessment. It does not detect future tampering unless run again; there is no claim of instant detection.
- This does not prove sensor-to-asset coverage, real OS log access, uptime, port exposure safety, or production readiness.
- Host/operational and dependency risk reviews, GitHub default-branch protection, and external security review remain release blockers.

## Reproducing tests

```sh
cd backend
python -m pytest -q tests/test_runtime_integrity_probe.py
python -m pytest -q
```

CI PostgreSQL and frontend jobs must also pass on the **published PR SHA** before calling this an automated-qualification pass.
