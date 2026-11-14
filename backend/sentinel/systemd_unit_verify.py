"""Verify the shipped collector unit with systemd's real Linux parser, offline.

This qualifies only static syntax and the separately reviewed local unit contract.
It does not install or run a service and never certifies a physical Linux host.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile

from .deployment_preflight import _unit

UNIT_RELATIVE = Path("deploy/linux/systemd/sentinel-ssh-collector.service")
APPROVED_PYTHON = "/opt/sentinel/venv/bin/python"
MAX_UNIT_BYTES = 8192
MAX_TOOL_OUTPUT = 8192
# systemd >= 259 (Ubuntu 26.04 runners) also parses unrelated host units pulled
# in as dependencies and warns about THEIR removed options (e.g. CPUAccounting=).
# Only that single, observed warning class is tolerated, and only when it names
# a vendor/host unit file by absolute path. Any other host diagnostic (unknown
# key, bad value, missing dependency, ...) still fails closed.
_HOST_UNIT_DIAGNOSTIC = re.compile(
    r"^(?:/usr/lib/systemd|/lib/systemd|/usr/local/lib/systemd|/etc/systemd|/run/systemd)"
    r"/[A-Za-z0-9@._/-]{1,200}:\d{1,6}: "
    r"Support for option [A-Za-z]{1,64}= has been removed and it is ignored$")


class UnitSyntaxError(ValueError):
    """Unit failed local policy or systemd syntax validation."""


class UnitToolUnavailable(RuntimeError):
    """systemd verifier absent, timed out, or could not execute."""


def verify_unit(unit_path: Path, *, analyzer: str | None = None,
                python_exe: str | None = None) -> dict:
    """Validate offline using the real parser; never invoke systemctl or a service.

    The install-time ExecStart uses a fixed venv interpreter that need not exist
    on the CI runner. Substitute *only that executable* in a throwaway copy,
    leaving all other shipped service and sandbox directives unchanged.
    """
    if platform.system() != "Linux":
        raise UnitToolUnavailable("Linux parser qualification unavailable")
    path = Path(unit_path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_UNIT_BYTES:
        raise UnitSyntaxError("Invalid shipped unit")
    try:
        data = path.read_bytes()
        raw = data.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise UnitSyntaxError("Unreadable shipped unit") from exc
    if b"\x00" in data or not data:
        raise UnitSyntaxError("Invalid shipped unit bytes")
    # This policy check rejects removed confinement, hidden execution hooks,
    # shell commands, duplicate settings, and configuration path drift.
    try:
        _unit(path, source=Path("/var/log/auth.log"),
              state_dir=Path("/var/lib/sentinel-sensor"),
              key_file=Path("/etc/sentinel/collector.key"),
              config_file=Path("/etc/sentinel/collector.conf"))
    except (OSError, ValueError) as exc:
        raise UnitSyntaxError("Unit violates the reviewed deployment contract") from exc

    marker = f"ExecStart={APPROVED_PYTHON} "
    if raw.count(marker) != 1:
        raise UnitSyntaxError("Unrecognized fixed service interpreter")
    executable = python_exe or sys.executable
    if not Path(executable).is_absolute() or not Path(executable).is_file() or re.search(r"\s", executable):
        raise UnitToolUnavailable("Local test interpreter unavailable")
    program = analyzer or shutil.which("systemd-analyze")
    if not program:
        raise UnitToolUnavailable("systemd-analyze unavailable")

    with tempfile.TemporaryDirectory(prefix="sentinel-unit-parser-") as parent:
        tmp = Path(parent) / UNIT_RELATIVE.name
        tmp.write_text(raw.replace(marker, f"ExecStart={executable} ", 1), encoding="utf-8")
        tmp.chmod(0o600)
        try:
            result = subprocess.run([program, "verify", str(tmp)],
                                    capture_output=True, text=True, encoding="utf-8",
                                    errors="replace", timeout=10, check=False,
                                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"})
        except (subprocess.TimeoutExpired, OSError, ValueError) as exc:
            raise UnitToolUnavailable("systemd parser could not complete") from exc
        host_diagnostics = _host_only_diagnostics(result, tmp)
    if host_diagnostics is None:
        # Critical: systemd-analyze can return 0 while warning that an unknown
        # or malformed sandbox directive was ignored. Treat ANY output that is
        # not provably about another host unit as failure.
        # Never echo output: it can contain runner-specific paths.
        raise UnitSyntaxError("systemd rejected or warned about the unit")
    return {"schema": "sentinel-systemd-parser-evidence-v1",
            "unit_sha256": hashlib.sha256(data).hexdigest(),
            "syntax_verified": True,
            "reviewed_contract_verified": True,
            "tested_using_temporary_interpreter": True,
            "ignored_host_unit_diagnostics": host_diagnostics,
            "service_started": False,
            "host_certified": False,
            "scope": "CI-hosted Linux parser; not service execution or host recovery"}


def _host_only_diagnostics(result: subprocess.CompletedProcess, unit_copy: Path) -> int | None:
    """Return the count of ignorable host-unit diagnostics, or None to fail.

    Fails on a non-zero exit, oversized output, stdout, or any stderr line that
    mentions the unit under test or is not a path-attributed host-unit warning.
    """
    if (result.returncode != 0 or result.stdout.strip()
            or len(result.stdout) > MAX_TOOL_OUTPUT or len(result.stderr) > MAX_TOOL_OUTPUT):
        return None
    ignored = 0
    for line in result.stderr.splitlines():
        if not line.strip():
            continue
        if (str(unit_copy) in line or unit_copy.name in line
                or not _HOST_UNIT_DIAGNOSTIC.fullmatch(line)):
            return None
        ignored += 1
    return ignored
