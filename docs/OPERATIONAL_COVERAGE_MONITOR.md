# v0.11 — Read-only operational coverage monitor

Sentinel includes an opt-in **local-only** coverage probe. It evaluates the
existing authenticated GET /api/v1/sensors inventory, independently
reconciles the reported sensor statuses and returns process exit codes.
It does NOT block traffic, create incidents, send messages, contact internet
hosts, or start a background service.

## Requirements

1. A migrated Sentinel API listening on **127.0.0.1:8000**.
2. At least one configured sensor. Explicit SENTINEL_SENSOR_ASSETS enrollment
   is recommended over first-contact binding.
3. An individually enrolled **viewer-scoped** credential. This tool does not
   need analyst or administrator permissions.
4. A private token file outside Git and any web-served directory. The file
   must be owned by the current OS user, readable only by the owner and be a
   regular file (no symlinks). It should contain the token and optional newline.

Linux (from backend/):

```bash
umask 077
mkdir -p "$HOME/.config/sentinel"
chmod 700 "$HOME/.config/sentinel"
# Provision your viewer token through an approved local secret-management method.
# Never paste it into a shell argument or commit it to GitHub.
chmod 600 "$HOME/.config/sentinel/coverage.token"
python -m scripts.check_sensor_coverage --token-file "$HOME/.config/sentinel/coverage.token"
python -m scripts.check_sensor_coverage --token-file "$HOME/.config/sentinel/coverage.token" --json
```

Exit codes:
- **0**: at least one enrolled sensor and all sensors showed recent accepted
  signed contact at the moment of polling.
- **2**: one or more enrolled sensors is **stale** or **never_seen**.
- **1**: coverage cannot be trusted (API unavailable, authentication failure,
  invalid inventory, unsafe token file, or malformed response). Treat this as
  a monitoring failure, never as proof of successful protection.

The --json mode emits aggregate counts only, not sensor IDs or secrets.
An operator can arrange external alerting using a local scheduler that reacts
to exit codes. No email, webhook, SMS, Slack, or remote alert delivery is
implemented by Sentinel in this release.

## Isolation and known limits

The tool connects only to literal loopback 127.0.0.1 over HTTP, to the fixed
/api/v1/sensors endpoint. No user-supplied hostnames, remote URLs, redirects,
proxies or DNS. The response size and connection timeout are bounded.

A heartbeat confirms recent contact accepted by the API, **not device
attestation or log completeness**. A stolen sensor key can forge contact for
its pinned asset. A persistent sensor may remain connected while its observed
log source is empty or compromised. The 180-second stale cutoff is a local
demonstration threshold and is not a production SLA.

Tests cover the real authenticated coverage API, never-seen → healthy
transition, fail-closed summary reconciliation, credential file permissions,
CLI return codes, and the hardcoded local destination. This does not qualify
a real Linux host installation, a systemd service, or production escalation.
