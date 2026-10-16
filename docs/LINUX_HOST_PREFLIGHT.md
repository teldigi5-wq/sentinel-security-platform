# Linux collector deployment preflight — v0.13

**Qualification level: static host checks, not real-host operational certification.**
No installation or OS service modifications are performed by this command. Use
only on Linux devices you own or are expressly authorized to monitor.

The preflight checks Linux system, dedicated unprivileged service identity,
private 0600 signing key access, readable regular syslog input, 0700 owned
state directory and existing cursor, restricted nonsecret metadata, and the
reviewed systemd unit hardening and path consistency. It never reads event lines
or transmits data. No key, log content or username appears in the JSON.

1. Review `docs/LINUX_SERVICE.md`; manually install the v0.12 unit, collector,
   service account, approved asset/sensor mapping and sensor signing key.
2. Before starting the service, run the preflight using the *same Python
   environment and unprivileged service account*:

   ```shell
   sudo -u sentinel-sensor /opt/sentinel/venv/bin/python -m scripts.preflight_linux_collector \
     --json-out /var/lib/sentinel-sensor/preflight-evidence.json
   ```

   The report is created once (0600) and is never overwritten; choose another
   filename for a later run. The backend package must be installed in that venv.
   If your installation uses nondefault files, pass absolute `--source`,
   `--state-dir`, `--key-file`, `--config-file`, `--unit-file` paths and ensure
   the installed unit references the same locations. The test-only `--fixture`
   option skips service-account qualification and marks that check unverified.
3. A successful preflight exits `0`; a failed preflight exits `2`. Evidence
   write failures abort without changing the old evidence file. **A zero exit
   is not a real-host qualification certificate.** Preserve the JSON and the
   corresponding reviewed config change in an access-controlled location.
4. Complete the actual operator-managed drill: verify log and key permissions;
   start the unit; inspect active process UID, port and journal; send an
   authorized synthetic test event; confirm signed ingestion and sensor health;
   stop/restart; induce temporary local backend unavailability; verify the
   collector exits safely, restarts and resumes; rotate and truncate the test
   log; then reboot the host and re-check cursor/data integrity. Record exact
   commands, timestamps, expected/observed outcomes and rollback plan.

CI tests only nonprivileged fixture behavior. The collector itself does not
perform firewall changes, execute scans or auto-remediate hosts. A static
preflight cannot prove that the systemd service starts, that telemetry is
complete, or that a real-host reboot/recovery drill succeeded.
