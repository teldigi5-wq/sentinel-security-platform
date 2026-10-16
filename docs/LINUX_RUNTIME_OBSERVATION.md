# v0.15 — Read-only Linux runtime qualification observations

This is an **operational evidence aid**, not automated certification or a host installer.
It does not call `systemctl start|stop|restart`, change permissions, read journal/log
contents, inject events, or connect to remote hosts. A passing report only describes
**one snapshot** of a running unit and an authenticated localhost API inventory.

## Prerequisites and trust boundaries

1. Use an **authorized, isolated** Linux host with the documented v0.12 systemd
   service installed, configured, and started by its administrator. First follow
   [`LINUX_HOST_PREFLIGHT.md`](LINUX_HOST_PREFLIGHT.md) while using an appropriate
   dedicated service account; this runtime tool does not replace that preflight.
2. Explicitly map the sensor in `SENTINEL_SENSOR_ASSETS` and configure its signing key.
   The systemd unit should be installed at
   `/etc/systemd/system/sentinel-ssh-collector.service`, with `User` and `Group`
   set to `sentinel-sensor`.
3. Run this **separate viewer-only observation tool** as a dedicated monitoring
   account. Put a scoped Sentinel viewer token in a regular file owned by that
   account with mode `0600`; do **not** put tokens in shell arguments, journald,
   systemd unit definitions, screenshots or public CI artifacts. Do not add this
   monitoring account to unnecessary privileged groups. The API must be listening
   locally on `127.0.0.1`; the tool will not resolve arbitrary hostnames.
4. Install the backend Python dependencies in a local venv; run from `backend/`.

```sh
python -m scripts.observe_linux_host \
  --sensor-id linux-ssh-01 \
  --token-file /path/to/private/viewer.token \
  --port 8000 \
  --json-out /path/to/private/unique-observation.json
```

`--json-out` must name a **new absolute path**. Evidence is `0600`, refuses
symlinks and never overwrites an existing file. Avoid publishing real-host evidence
without first reviewing its metadata. The report never prints credentials, full
local paths, source IP addresses or raw authentication logs.

## What is verified

- A fixed, bounded, 5-second `systemctl show` read of this exact service. The
  expected unit path, loaded/running state, unprivileged identity, PID and absence
  of pending daemon reload are checked. The observed restart counter is reported
  **without implying any controlled restart drill occurred**.
- A bounded authenticated `/api/v1/sensors` query made only to `127.0.0.1` using
  a private viewer token file. The server's inventory totals are recomputed and
  checked for contradictions, and the **requested sensor ID** must have healthy
  recent contact and explicit asset enrollment.
- Read-only checks produce `0` (all six conditions passed), `2` (a clear
  coverage/service gap), or `1` (unknown: unavailable service/API, invalid token,
  missing sensor, malformed results). A status code `0` **never means the host is
  fully protected or production-certified**.

## Limitations and actual host qualification

This check does **not** prove that systemd has survived a real boot, that
journald/rsyslog files are readable after rotation, or that every relevant security
record was captured. A healthy sensor can still be compromised. Do not copy a CI
fixture report and label it real-host evidence.

Before production-readiness claims, an authorized operator should separately
record host OS/version, service installation review, privileged install approval,
manual restart/reboot recovery results, live benign SSH-failure ingestion with
sensitive data redacted, actual rotation behavior, outage and recovery observation,
rollback procedure, backup recovery, and operator sign-off. Keep those artifacts in
access-controlled storage outside the public repository.
