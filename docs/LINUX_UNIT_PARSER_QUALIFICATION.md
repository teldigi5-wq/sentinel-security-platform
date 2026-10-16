# Linux systemd unit parser qualification — GitHub-hosted runner

**Scope:** the checked-in SSH collector systemd unit's syntax and fixed security
contract are checked using the **real `systemd-analyze verify` executable** on a
Linux GitHub Actions runner. This is an offline validation, **not** a service
installation, successful service start, log access check, host reboot or production
security certification. It requires **no Linux computer or VM from the user**.

## What actually executes

The `linux-recovery-drill` job calls:

```sh
cd backend
python -m scripts.verify_linux_service_unit --json
python -m pytest -q tests/test_systemd_unit_verify.py
```

`verify_linux_service_unit` uses the approved, committed unit only. It checks
required service directives and paths with Sentinel's strict preflight contract,
then checks the unit with systemd's own parser. Since the install-time Python
binary is deliberately located under `/opt/sentinel/venv`, and GitHub runners do
not have Sentinel installed there, the parser runs against a **temporary private
copy** with only that interpreter path replaced by the current verified Python
binary. It does not write to `/etc/systemd/system`, call `systemctl`, start a
service, read `/var/log/auth.log`, or open a network connection.

**Important:** `systemd-analyze verify` sometimes returns success (`exit 0`)
even when it printed `Unknown key` or `Failed to parse` diagnostics and ignored
a hardening directive. The guard deliberately **rejects any parser output**, as
well as any nonzero exit code, oversized output, missing parser or timeout.
Negative tests cover an unknown systemd key, invalid values, unreviewed
execution hooks, weakened IP isolation and missing analyzer.

Successful output resembles:

```json
{
  "host_certified": false,
  "reviewed_contract_verified": true,
  "schema": "sentinel-systemd-parser-evidence-v1",
  "scope": "CI-hosted Linux parser; not service execution or host recovery",
  "service_started": false,
  "syntax_verified": true,
  "tested_using_temporary_interpreter": true,
  "unit_sha256": "<digest of reviewed unit bytes>"
}
```

The `unit_sha256` identifies the exact source bytes tested. It is a plain hash,
not a signature or proof of runtime confinement. Passing the parser does not
guarantee the host supports every directive at the desired privilege level.

## Still blocked before release

The real-host qualification remains open in
[Issue #35](https://github.com/teldigi5-wq/sentinel-security-platform/issues/35).
An authorized Linux host needs actual systemd install/restart, log permissions,
authentication log rotation, signed telemetry, backend outage/recovery, real
reboot evidence, rollback and human sign-off. Independent security review stays
open in [Issue #36](https://github.com/teldigi5-wq/sentinel-security-platform/issues/36).

Do **not** substitute the passing GitHub Linux runner job for either requirement.
