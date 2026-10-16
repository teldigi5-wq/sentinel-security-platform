"""Read-only Linux runtime observations. Never claims full host certification.

Fixed systemctl invocation and localhost-only credential-scoped coverage check.
Does not restart, install, enable, inject traffic, or read host journal entries.
"""
from __future__ import annotations

import platform
import re
import subprocess
from typing import Callable

from .coverage_probe import CoverageProbeError, fetch_coverage

UNIT = "sentinel-ssh-collector.service"
UNIT_PATH = f"/etc/systemd/system/{UNIT}"
_FIELDS = (
    "Id", "LoadState", "ActiveState", "SubState", "User", "Group",
    "FragmentPath", "MainPID", "NRestarts", "NeedDaemonReload",
)
_COMMAND = ("/usr/bin/systemctl", "--no-pager", "--no-ask-password",
            "show", "--property=" + ",".join(_FIELDS), UNIT)


class HostObservationError(RuntimeError):
    """A safe error that never contains systemctl stderr, paths or tokens."""


def _systemctl(runner: Callable = subprocess.run) -> dict[str, str | int]:
    try:
        finished = runner(
            list(_COMMAND), capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=5, check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        raise HostObservationError("Systemd status unavailable") from exc
    if finished.returncode != 0 or not isinstance(finished.stdout, str) or len(finished.stdout) > 8192:
        raise HostObservationError("Systemd status unavailable")
    fields: dict[str, str] = {}
    for line in finished.stdout.splitlines():
        if not line:
            continue
        if "=" not in line:
            raise HostObservationError("Malformed systemd status")
        name, value = line.split("=", 1)
        if name not in _FIELDS or name in fields or len(value) > 256:
            raise HostObservationError("Malformed systemd status")
        fields[name] = value
    if set(fields) != set(_FIELDS):
        raise HostObservationError("Incomplete systemd status")
    if not (fields["MainPID"].isascii() and fields["MainPID"].isdecimal()
            and fields["NRestarts"].isascii() and fields["NRestarts"].isdecimal()):
        raise HostObservationError("Malformed systemd counters")
    pid = int(fields["MainPID"])
    restarts = int(fields["NRestarts"])
    if pid > 2 ** 31 - 1 or restarts > 2 ** 31 - 1:
        raise HostObservationError("Invalid systemd counters")
    observed = {
        "unit_loaded": fields["Id"] == UNIT and fields["LoadState"] == "loaded"
                       and fields["FragmentPath"] == UNIT_PATH,
        "service_running": fields["ActiveState"] == "active"
                           and fields["SubState"] == "running" and pid > 1,
        "service_unprivileged": fields["User"] == "sentinel-sensor"
                                and fields["Group"] == "sentinel-sensor",
        "unit_config_current": fields["NeedDaemonReload"] == "no",
        "restart_count_observed": restarts,
    }
    return observed


def observe(*, sensor_id: str, port: int, token: str,
            runner: Callable = subprocess.run,
            probe: Callable = fetch_coverage,
            system_name: str | None = None) -> dict:
    """Return bounded sanitized evidence; do not include identifiers, raw logs or keys."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", sensor_id):
        raise HostObservationError("Invalid sensor identifier")
    if (system_name if system_name is not None else platform.system()) != "Linux":
        raise HostObservationError("Linux systemd host required")

    service = _systemctl(runner=runner)
    try:
        coverage = probe(port=port, token=token)
    except CoverageProbeError as exc:
        raise HostObservationError("Authenticated local coverage unavailable") from exc

    matches = [entry for entry in coverage.sensor_states if entry[0] == sensor_id]
    if len(matches) != 1:
        raise HostObservationError("Requested sensor missing from validated inventory")
    _, status, mode = matches[0]
    checks = {
        "systemd_unit_loaded": service["unit_loaded"],
        "systemd_running": service["service_running"],
        "systemd_unprivileged": service["service_unprivileged"],
        "systemd_config_current": service["unit_config_current"],
        "sensor_recent_contact": status == "healthy",
        "sensor_explicitly_enrolled": mode == "explicit",
    }
    return {
        "schema": "sentinel-linux-runtime-observation-v1",
        "scope": "read-only-current-linux-runtime",
        "all_checks_passed": all(checks.values()),
        "checks": [{"id": name, "result": "pass" if passed else "fail"}
                   for name, passed in checks.items()],
        "sensor_contact": status,
        "sensor_binding": mode,
        "restart_count_observed": service["restart_count_observed"],
        "host_certified": False,
        "limitations": [
            "one observation is not a restart or reboot drill",
            "authenticated contact is not endpoint attestation",
            "no log content, sensor event completeness or host security assessed",
        ],
    }
