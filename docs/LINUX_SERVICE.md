# v0.12 Linux systemd deployment contract (not yet real-host certified)

**Status:** systemd unit and key-loading logic are fixture-tested in CI. One
owner-operated lab host (WSL2 Ubuntu, single self-run operator, 2026-11-22) has
installed the unit under a dedicated non-root account, passed the static
preflight, and passed all four `qualify_linux_recovery` checkpoints (baseline,
restart, rotation, reboot) with offline verification. That is a lab observation,
not a certificate: there is no independent reviewer, the rotation was forced and
the "reboot" was a WSL VM restart, and outage, backup/restore and rollback drills
remain open (see issue #35, which stays open). Do not advertise this as
production hardening certification.

## Findings from the first real-host run

These are practical details the fixtures did not surface:

- **systemd must be PID 1.** On WSL2 confirm with `ps -p 1 -o comm=`.
- **Explicit enrollment is required for a passing baseline.** The qualification
  tool needs the sensor to be `healthy` *and* `explicit`; set
  `SENTINEL_SENSOR_ASSETS` (single-quoted JSON in `.env`, or the shell splits it
  at the space) and use the same asset name the sensor is already pinned to.
- **Backend `.env` is read only at startup.** After changing operators, sensor
  keys or enrollment, restart the backend before testing.
- **The key file must be owned by the service account** (not the installing
  user), mode `0600`; the collector checks ownership against its own UID.
- **Use a viewer-role token for the observer**, enrolled through
  `SENTINEL_OPERATORS`; the qualification tool only calls endpoints that any
  role may read, and an admin-only endpoint must still return 403 for it.
- **Stock `logrotate` may skip `auth.log`** where `/var/log` is group-writable
  (seen on WSL2). A one-off config with `su root syslog` limited to `auth.log`
  rotated it; do not change production rotation just to pass a drill.
- **The unit is not enabled at boot** by this procedure; start it manually after
  a reboot, or enable it as a separate operational decision.

## Scope and prerequisites

- Only a Linux machine you own or are explicitly authorized to monitor.
- This service reads `/var/log/auth.log` (Debian/Ubuntu syslog); systems using
  journald only or `/var/log/secure` need a separately reviewed configuration.
- SENTINEL API runs on `127.0.0.1:8000` on the **same host**. Remote transport
  is deliberately unsupported. Backend enrollment must map the sensor to its
  exact approved asset, and sensor key must match the backend's configured key.
- Install backend in `/opt/sentinel/venv` (matching `ExecStart`) and grant the
  dedicated `sentinel-sensor` account **only** read access to the SSH log (often
  `adm` group) and ownership of `/etc/sentinel/collector.key`. Do not run as root.
- The sample unit uses a fixed interpreter, source, state and port. Review all
  paths against your host before installation. `ReadWritePaths` is not needed
  because systemd manages the private `StateDirectory`.

## Manual review and enrollment steps

1. Create a system account named `sentinel-sensor` with no interactive login.
   Before granting supplementary `adm`, verify the group grants no unnecessary
   access on this distribution. **If it does, use narrowly scoped ACLs instead.**
2. Create `/etc/sentinel/` owned by root, mode 0755; create `collector.conf`
   from `deploy/linux/collector.conf.example`, owned by root and not writable
   by the sensor account. Values are deliberately nonsecret stable identifiers.
3. Provision a distinct random high-entropy signing key in
   `/etc/sentinel/collector.key`, owned by `sentinel-sensor` mode **0600**.
   Do not put it in the unit, environment file, shell history or Git. The
   `--sensor-key-file` option refuses symlinks, nonregular files and weak modes.
4. Ensure `SENTINEL_SENSOR_KEYS` is **absent** from the collector service
   environment: simultaneous environment and file secrets fail closed.
5. Copy the reviewed service unit to `/etc/systemd/system/`, run
   `systemctl daemon-reload`, then manually `systemctl start
   sentinel-ssh-collector.service` after ensuring the backend is available.
   Enabling across reboot is a separate explicit operational approval.
6. Verify local logs, sensor health and signed ingest (including an authorized
   test failure event). Confirm secrets and usernames do not appear in journal.
7. Stop and restart the service; append a test fixture; check cursor continuity
   and exactly-once *logical* nonce handling. Rotate and truncate the source
   log and confirm the service recovers. Reboot tests still need a real host.
8. Exercise backend outage and restart: collector should stop with an error
   and systemd should restart it; the cursor must not advance past unsent data.

## Limitations and safety decisions

- `ProtectSystem=strict` and `StateDirectoryMode=0700` restrict writes, but
  `SupplementaryGroups=adm` may provide broader log visibility than desirable.
- `IPAddressAllow=localhost` requires systemd network-access filtering support;
  do not silently remove it on older systems.
- The source is a syslog file, not journald. Inode rotation and truncation are
  handled by existing collector code, but the running service is not tested on
  an actual rotated file in CI.
- The code currently uses collection time as observed time when syslog cannot
  reliably supply timezone/year. Do not claim accurate original occurrence time.
- No automatic blocking, remote upload, privileged probing or host firewall
  reconfiguration is provided. The `collector.conf` contains no secrets.
- Validate coverage using the separate local read-only coverage probe, and
  investigate any sensor reported stale or never seen. Heartbeat is not proof
  of endpoint compromise resistance or completeness of coverage.
