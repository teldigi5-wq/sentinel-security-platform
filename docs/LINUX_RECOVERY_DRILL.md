# Linux sensor: isolated recovery drill (v0.14)

The offline recovery drill uses real Sentinel FastAPI request handling, HMAC
verification, SQLite migrations, detection, audit chain, and Linux collector
cursor logic **with private synthetic files**. It is neither a systemd test nor
an actual Linux-host certification.

From `backend/` after installing test dependencies:

```sh
python -m scripts.drill_linux_collector --json-out /absolute/private/path/unused-evidence.json
```

The evidence file is created exclusively, permission `0600`, and is never
replaced. Do not store the evidence alongside credentials. A nonzero exit is a
failed qualification and must block promotion.

## Checks

- Start with historical entries: no implicit backfill or false initial alert.
- Append five SSH failures: the **actual** API creates one evidence-linked alert.
- Re-poll after simulated restart: cursor avoids duplicate events.
- Simulate an ACK lost *after successful submission*: the retry reuses its
  deterministic nonce and the backend reports duplicate (409).
- Simulate a log rotation: new inode, fresh cursor generation and one event.
- Send signed heartbeat, inspect coverage, artificially age server record by
  four minutes to simulate an outage, then recover with a new heartbeat.
- Verify final event count and authenticated audit-chain integrity.

The report includes only check identifiers, statuses, count and declared
limitations. No signing key, operator token, source IP, filename, username or
raw syslog line is included.

## Evidence levels

1. **Isolated fixture (this workflow):** proves code-path behavior only.
2. **Real-host static preflight (`scripts.preflight_linux_collector`):** checks
   file access, service identity and configured hardening without mutating the
   machine. `host_certified` remains `false`.
3. **Real-host operation (not done):** authorized Linux host must actually run
   the dedicated non-root service, survive restart/reboot, demonstrate rotation
   and retention, detect a deliberately generated authorized event, and recover
   from loss of local API connectivity. Keep scrubbed `journalctl` output,
   restart counts, signed heartbeat coverage and verified event/alert evidence.

Do not claim tier 3 on the basis of tier 1 or CI results. Never store secret
contents in an issue or CI artifact. No automatic blocking or offensive action
is part of this milestone.
