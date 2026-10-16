"""Non-privileged, operator-driven Linux recovery evidence checkpoints.

These snapshots are NOT remotely attested or independently immutable. Only observed
service state, authenticated loopback API responses, and file metadata are used.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Callable

from .coverage_probe import CoverageProbeError, fetch_coverage
from .host_observation import HostObservationError, UNIT, observe
from .integrity_probe import IntegrityProbeError, fetch_integrity

PHASES = ("baseline", "post_restart", "post_rotation", "post_reboot")
FORMAT = "sentinel-host-recovery-witness-v1"
UNIT_COMMAND = ("/usr/bin/systemctl", "--no-pager", "--no-ask-password", "show",
                "--property=Id,InvocationID", UNIT)
SOURCE = Path("/var/log/auth.log")
BOOT_FILE = Path("/proc/sys/kernel/random/boot_id")
MAX_RECORD_BYTES = 16384


class HostAcceptanceError(RuntimeError):
    """All outward-facing exceptions have non-sensitive fixed messages."""


def read_invocation(runner: Callable = subprocess.run) -> str:
    """Read a service lifetime marker; never start or modify a systemd unit."""
    try:
        proc = runner(list(UNIT_COMMAND), capture_output=True, text=True,
                      encoding="utf-8", errors="replace", timeout=5,
                      check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise HostAcceptanceError("Service invocation unavailable") from exc
    if proc.returncode != 0 or not isinstance(proc.stdout, str) or len(proc.stdout) > 256:
        raise HostAcceptanceError("Service invocation unavailable")
    lines = proc.stdout.strip().splitlines()
    if len(lines) != 2 or any("=" not in line for line in lines):
        raise HostAcceptanceError("Service invocation unavailable")
    fields = dict(line.split("=", 1) for line in lines)
    if (set(fields) != {"Id", "InvocationID"} or fields["Id"] != UNIT
            or not re.fullmatch(r"[0-9a-fA-F]{32}", fields["InvocationID"])):
        raise HostAcceptanceError("Service invocation unavailable")
    return fields["InvocationID"].lower()


def read_boot_id() -> str:
    try:
        raw = BOOT_FILE.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise HostAcceptanceError("Boot identity unavailable") from exc
    if not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", raw):
        raise HostAcceptanceError("Boot identity unavailable")
    return raw.lower()


def read_log_identity() -> str:
    """Stat a fixed read-only log source; never consume authentication log data."""
    try:
        st = SOURCE.lstat()
    except OSError as exc:
        raise HostAcceptanceError("SSH authentication log metadata unavailable") from exc
    if not stat.S_ISREG(st.st_mode) or st.st_ino <= 0:
        raise HostAcceptanceError("SSH authentication log metadata unavailable")
    return f"{st.st_dev}:{st.st_ino}"


def _fingerprint(run_id: str, value: str, domain: str) -> str:
    return hashlib.sha256(f"sentinel-host-witness-v1:{run_id}:{domain}:{value}".encode()).hexdigest()


def _record_bytes(record: dict) -> bytes:
    return (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def _private_directory(path: Path) -> None:
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise HostAcceptanceError("Evidence directory must be private, real and absolute")
    st = path.stat()
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise HostAcceptanceError("Evidence directory must be owned by the operator with mode 0700")


def _read_record(path: Path) -> tuple[dict, str]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as f:
            info = os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise HostAcceptanceError("Existing evidence file is not private")
            raw = f.read(MAX_RECORD_BYTES + 1)
    except OSError as exc:
        raise HostAcceptanceError("Previous evidence unavailable") from exc
    if len(raw) > MAX_RECORD_BYTES:
        raise HostAcceptanceError("Previous evidence too large")
    try:
        value = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise HostAcceptanceError("Invalid previous evidence") from exc
    if (not isinstance(value, dict) or value.get("schema") != FORMAT
            or value.get("phase") not in PHASES or value.get("status") != "pass"
            or not re.fullmatch(r"[0-9a-f]{32}", str(value.get("run_id", "")))
            or not isinstance(value.get("snapshot"), dict)
            or not isinstance(value.get("observed_at_utc"), str)):
        raise HostAcceptanceError("Previous evidence is not passing and compatible")
    for k in ("boot", "invocation", "log"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(value["snapshot"].get(k, ""))):
            raise HostAcceptanceError("Malformed previous evidence marker")
    for k in ("events", "heartbeats"):
        if type(value["snapshot"].get(k)) is not int or value["snapshot"][k] < 0:
            raise HostAcceptanceError("Malformed previous evidence counters")
    return value, hashlib.sha256(raw).hexdigest()


def _store(path: Path, record: dict) -> None:
    payload = _record_bytes(record)
    if len(payload) > MAX_RECORD_BYTES:
        raise HostAcceptanceError("Evidence size bound exceeded")
    fd = None
    created = False
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        created = True
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        if fd is not None:
            os.close(fd)
        if created:
            path.unlink(missing_ok=True)
        raise HostAcceptanceError("Could not safely create new checkpoint evidence") from exc


def capture(*, phase: str, directory: Path, sensor_id: str, port: int, token: str,
            observer: Callable = observe,
            coverage_fetch: Callable = fetch_coverage,
            integrity_fetch: Callable = fetch_integrity,
            instance_probe: Callable = read_invocation,
            boot_probe: Callable = read_boot_id,
            log_probe: Callable = read_log_identity,
            clock: Callable = lambda: datetime.now(timezone.utc),
            system_name: str | None = None) -> dict:
    """Capture one phase and compare against predecessor; never mutate host services.

    The operator independently triggers restart, log rotation and reboot. A
    PASS proves the expected *observations* only, not causation or log completeness.
    """
    if phase not in PHASES or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", sensor_id):
        raise HostAcceptanceError("Invalid qualification phase or sensor")
    if (system_name if system_name is not None else platform.system()) != "Linux":
        raise HostAcceptanceError("A Linux host is required")
    if type(port) is not int or not 1 <= port <= 65535:
        raise HostAcceptanceError("Invalid local API port")
    directory = Path(directory)
    if phase == "baseline":
        if not directory.is_absolute() or directory.exists() or directory.is_symlink():
            raise HostAcceptanceError("Baseline requires a new absolute evidence directory")
        try:
            directory.mkdir(mode=0o700)
        except OSError as exc:
            raise HostAcceptanceError("Cannot create private evidence directory") from exc
    _private_directory(directory)
    position = PHASES.index(phase)
    previous, previous_sha = None, None
    if position:
        previous, previous_sha = _read_record(directory / f"{PHASES[position-1]}.json")
    run_id = previous["run_id"] if previous else secrets.token_hex(16)
    output = directory / f"{phase}.json"
    if output.exists() or output.is_symlink():
        raise HostAcceptanceError("Evidence checkpoint already exists; no overwrite")

    try:
        before_instance = instance_probe()
        runtime = observer(sensor_id=sensor_id, port=port, token=token)
        inventory = coverage_fetch(port=port, token=token)
        integrity = integrity_fetch(port=port, token=token)
        boot = boot_probe()
        log = log_probe()
        after_instance = instance_probe()
    except (CoverageProbeError, IntegrityProbeError, HostObservationError, HostAcceptanceError) as exc:
        raise HostAcceptanceError("Unable to gather complete current host evidence") from exc
    activity = getattr(inventory, "sensor_activity", ())
    matching = [x for x in activity if x[0] == sensor_id]
    state = [x for x in inventory.sensor_states if x[0] == sensor_id]
    if len(matching) != 1 or len(state) != 1:
        raise HostAcceptanceError("Selected sensor counters unavailable")
    _, events, heartbeats = matching[0]
    checks = {
        "read_only_service_running": runtime["all_checks_passed"] is True,
        "authenticated_event_integrity": integrity.clear is True,
        "sensor_explicit_and_healthy": state[0][1:] == ("healthy", "explicit"),
        "stable_service_instance": before_instance == after_instance,
    }
    snapshot = {
        "boot": _fingerprint(run_id, boot, "boot"),
        "invocation": _fingerprint(run_id, before_instance, "unit"),
        "log": _fingerprint(run_id, log, "log-inode"),
        "events": events,
        "heartbeats": heartbeats,
    }
    if previous:
        old = previous["snapshot"]
        earlier = datetime.fromisoformat(previous["observed_at_utc"])
        now = clock()
        checks["later_observation"] = now.tzinfo is not None and now > earlier
        checks["nondecreasing_sensor_counters"] = events >= old["events"] and heartbeats >= old["heartbeats"]
        if phase == "post_restart":
            checks["same_boot_after_restart"] = snapshot["boot"] == old["boot"]
            checks["new_service_invocation"] = snapshot["invocation"] != old["invocation"]
            checks["new_sensor_contact"] = events > old["events"] or heartbeats > old["heartbeats"]
        elif phase == "post_rotation":
            checks["same_boot_after_rotation"] = snapshot["boot"] == old["boot"]
            checks["authentication_log_rotated"] = snapshot["log"] != old["log"]
            checks["new_event_after_rotation"] = events > old["events"]
        elif phase == "post_reboot":
            checks["different_boot_after_reboot"] = snapshot["boot"] != old["boot"]
            checks["new_sensor_contact"] = events > old["events"] or heartbeats > old["heartbeats"]
    else:
        now = clock()
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise HostAcceptanceError("An accurate UTC clock is required")
    record = {
        "schema": FORMAT, "phase": phase, "run_id": run_id,
        "observed_at_utc": now.isoformat(), "previous_sha256": previous_sha,
        "checks": {name: "pass" if ok else "gap" for name, ok in checks.items()},
        "status": "pass" if all(checks.values()) else "gap",
        "snapshot": snapshot, "host_certified": False,
        "assurance": "operator-driven observations; no independent host attestation or complete log verification",
    }
    _store(output, record)
    return record


def verify(directory: Path) -> dict:
    """Offline sequence validation; not cryptographic proof against full rewrite."""
    directory = Path(directory)
    _private_directory(directory)
    reports: list[dict] = []
    last_sha = None
    last_time = None
    run_id = None
    for phase in PHASES:
        report, sha = _read_record(directory / f"{phase}.json")
        if report["phase"] != phase or report.get("previous_sha256") != last_sha:
            raise HostAcceptanceError("Checkpoint sequence is incomplete or changed")
        if run_id is not None and report["run_id"] != run_id:
            raise HostAcceptanceError("Checkpoint run identity differs")
        if not isinstance(report.get("checks"), dict) or not report["checks"] or any(
                value != "pass" for value in report["checks"].values()):
            raise HostAcceptanceError("Non-passing checkpoint evidence")
        try:
            when = datetime.fromisoformat(report["observed_at_utc"])
        except (ValueError, TypeError) as exc:
            raise HostAcceptanceError("Invalid evidence timestamp") from exc
        if when.utcoffset() != timedelta(0) or (last_time is not None and when <= last_time):
            raise HostAcceptanceError("Out-of-order evidence timestamps")
        last_time, last_sha, run_id = when, sha, report["run_id"]
        reports.append(report)
    snapshots = [r["snapshot"] for r in reports]
    for index in range(1, len(snapshots)):
        before, after = snapshots[index - 1], snapshots[index]
        if (after["events"] < before["events"] or
                after["heartbeats"] < before["heartbeats"]):
            raise HostAcceptanceError("Sensor counters moved backwards")
    if (snapshots[0]["boot"] != snapshots[1]["boot"] or
        snapshots[1]["boot"] != snapshots[2]["boot"] or
        snapshots[2]["boot"] == snapshots[3]["boot"] or
        snapshots[0]["invocation"] == snapshots[1]["invocation"] or
        snapshots[1]["log"] == snapshots[2]["log"] or
        not snapshots[2]["events"] > snapshots[1]["events"] or
        not (snapshots[1]["events"] > snapshots[0]["events"] or
             snapshots[1]["heartbeats"] > snapshots[0]["heartbeats"]) or
        not (snapshots[3]["events"] > snapshots[2]["events"] or
             snapshots[3]["heartbeats"] > snapshots[2]["heartbeats"])):
        raise HostAcceptanceError("Checkpoint transitions do not match expected observations")
    return {
        "schema": FORMAT, "checkpoints": list(PHASES), "checkpoint_count": 4,
        "result": "observed_phases_passed", "host_certified": False,
        "final_sha256": last_sha,
        "limitations": "read-only host observations without independent attestation, log completeness or production certification",
    }