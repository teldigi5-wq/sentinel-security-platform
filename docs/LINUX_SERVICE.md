# v0.12 Linux systemd deployment contract (not yet real-host certified)

**Status:** systemd unit and key-loading logic are fixture-tested, but no actual
Linux service installation, log permissions, reboot recovery, or daemon behavior
has been verified. Do not advertise this as production hardening certification.

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
