# Operator-driven Linux host recovery evidence (v0.25)

**Status: read-only measurement tool, NOT an automatic installer, service controller,
production certificate, penetration test, or remote attestation.** Synthetic CI tests
validate code only. The project has **not** executed this procedure on your machine.

## Before use

Use an authorized, isolated Linux host with a working `/var/log/auth.log` based
Sentinel SSH collector (`sentinel-ssh-collector.service`) and a local Sentinel API.
The backend must persist event/audit data across reboots. Configure explicit
sensor-to-asset enrollment. First follow `LINUX_SERVICE.md`,
`LINUX_HOST_PREFLIGHT.md`, `LINUX_RUNTIME_OBSERVATION.md` and
`RUNTIME_INTEGRITY_MONITOR.md`. Obtain real administrative approval for any
restart, rotation or reboot; these are **external manual actions**, not performed
by Sentinel's qualification tool. Never force a log rotation on an important
system just to pass a development test.

Use a **separate non-root observer account** with only read/execute access to the
installed application, `systemctl show` and `stat` of `/var/log/auth.log`.
Keep its scoped viewer token in a user-owned, mode 0600 regular file, outside
the project repository. The tool queries only `127.0.0.1` for sensor coverage
and audit status; it never makes remote HTTP requests or reads authentication
log contents. No raw host IP, boot ID, invocation ID, credential or file path
is written into evidence. Fingerprints are session-scoped and private.

In `backend/`, after installing the reviewed dependencies and with a private
parent directory available, run **each stage on the same machine/account**:

```sh
python -m scripts.qualify_linux_recovery --phase baseline \
  --evidence-dir /private/sentinel-witness-unique --sensor-id linux-ssh-01 \
  --token-file /private/viewer.token --port 8000
```

Only if the baseline reports `pass`, have the authorized operator perform and
verify an actual service restart. After it is healthy again and a new signed
heartbeat/event is ingested, capture:

```sh
python -m scripts.qualify_linux_recovery --phase post_restart \
  --evidence-dir /private/sentinel-witness-unique --sensor-id linux-ssh-01 \
  --token-file /private/viewer.token --port 8000
```

Next, **after natural, authorized rotation of `/var/log/auth.log`** and after an
actual benign SSH authentication failure is registered in the local Sentinel
backend (do not automate log injection), capture `--phase post_rotation` with
the same other arguments. It requires a changed log inode **and** an increase
in the enrolled sensor's ingested event counter. A rotated inode alone is not
evidence of continued ingestion or complete log handling.

Finally, after an authorized full machine reboot (including restored API and
collector) and new signed sensor contact, capture `--phase post_reboot` with
the same other arguments. This stage checks a changed kernel boot identifier;
a service restart alone cannot satisfy it. To verify the complete private
checkpoint sequence offline:

```sh
python -m scripts.qualify_linux_recovery \
  --evidence-dir /private/sentinel-witness-unique --verify
```

`baseline` requires a **new absolute directory** (created mode 0700). All stages
write a new private 0600 JSON file and refuse overwrites or symlinks. A later
stage must follow a passing predecessor. Each file holds a SHA-256 link to the
previous file; checking the sequence detects partial replacement, not a
malicious actor who can rewrite the entire directory. Preserve files in
restricted off-host storage after reviewing them; they are not signed by an
independent authority. Do not commit them to GitHub or publicly share screenshots.

Exit codes: `0` passing observation, `2` observed gap (the checkpoint is still
saved privately), `1` unknown/unavailable/incompatible. A check returning `0`
**does not certify the host as protected**. This cannot prove why a reboot,
restart or log rotation happened, all-event completeness, the honesty of a
compromised sensor, durability, external immutability, or the safety of the
host OS. Human review, a formal threat model, security assessment, and a
separate operational acceptance sign-off remain required.
