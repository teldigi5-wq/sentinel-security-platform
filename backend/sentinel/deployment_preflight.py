"""Offline, non-destructive Linux collector service preflight.

Passing a preflight is NOT proof of real-host systemd operation, detection
coverage, or recovery. Never include source logs or signing keys in reports.
"""
from __future__ import annotations

import os
from pathlib import Path
import platform
import pwd
import re
import shlex
import stat
from typing import Mapping

from .collectors.linux_ssh import (
    CollectorError, _open_log, _read_state, read_private_sensor_key,
)

SENSOR_RE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
ASSET_RE = re.compile(r"[A-Za-z0-9._:-]{1,100}\Z")
REQUIRED_UNIT = (
    "Type=simple", "User=sentinel-sensor", "Group=sentinel-sensor",
    "StateDirectory=sentinel-sensor", "StateDirectoryMode=0700",
    "Restart=on-failure", "NoNewPrivileges=yes", "PrivateTmp=yes",
    "ProtectSystem=strict", "ProtectHome=yes", "CapabilityBoundingSet=",
    "IPAddressDeny=any", "IPAddressAllow=localhost", "UMask=0077",
)


def _read_regular(path: Path, *, max_bytes: int, forbid_group_write: bool = True) -> str:
    if not path.is_absolute() or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("Absolute file path and no-follow support required")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError("File cannot be opened safely") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (forbid_group_write and info.st_mode & 0o022):
            raise ValueError("File must be regular and not group/other writable")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            data = stream.read(max_bytes + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if len(data) > max_bytes:
        raise ValueError("File exceeds preflight size limit")
    try:
        return data.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("File is not UTF-8") from exc


def _config(path: Path) -> Mapping[str, str]:
    raw = _read_regular(path, max_bytes=4096)
    result = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("Malformed collector metadata")
        name, value = line.split("=", 1)
        if name not in {"SENTINEL_SENSOR_ID", "SENTINEL_ASSET_ID"} or name in result:
            raise ValueError("Duplicate or unapproved collector metadata")
        result[name] = value
    if set(result) != {"SENTINEL_SENSOR_ID", "SENTINEL_ASSET_ID"}:
        raise ValueError("Missing collector metadata")
    if not SENSOR_RE.fullmatch(result["SENTINEL_SENSOR_ID"]) or not ASSET_RE.fullmatch(result["SENTINEL_ASSET_ID"]):
        raise ValueError("Collector identifiers are invalid")
    return result


def _unit(path: Path, *, source: Path, state_dir: Path, key_file: Path, config_file: Path) -> None:
    content = _read_regular(path, max_bytes=8192)
    directives: dict[str, str] = {}
    section = None
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line
            continue
        if "=" not in line:
            raise ValueError("Malformed unit directive")
        if section == "[Service]":
            name, value = line.split("=", 1)
            # Duplicate service directives are ambiguous: later systemd values
            # may override hardening. Reject rather than simulate systemd precedence.
            if name in directives:
                raise ValueError("Duplicate service directive")
            directives[name] = value
    if any(directives.get(name) != value for name, value in
           (item.split("=", 1) for item in REQUIRED_UNIT)):
        raise ValueError("Missing mandatory systemd confinement directive")
    if directives.get("EnvironmentFile") != str(config_file):
        raise ValueError("Service metadata path does not match")
    # Any additional Exec* hook runs unreviewed code, even if ExecStart is safe.
    if any(name.startswith("Exec") and name != "ExecStart" for name in directives):
        raise ValueError("Unreviewed service execution hook")
    command = directives.get("ExecStart", "")
    try:
        args = shlex.split(command)
    except ValueError as exc:
        raise ValueError("Malformed collector command") from exc
    if not args or args[0] != "/opt/sentinel/venv/bin/python":
        raise ValueError("Collector interpreter does not match approved installation")
    required_pairs = (
        ("-m", "sentinel.collectors.linux_ssh"),
        ("--source", str(source)),
        ("--state", str(state_dir / "ssh-cursor.json")),
        ("--sensor-key-file", str(key_file)),
        ("--port", "8000"),
    )
    if any(not any(args[i:i + 2] == [flag, value] for i in range(len(args) - 1))
           for flag, value in required_pairs):
        raise ValueError("Collector command arguments differ from approved paths")
    if "--follow" not in args or "--backfill" in args or any(
            token.startswith("/bin/sh") or token.startswith("/bin/bash") for token in args):
        raise ValueError("Collector command includes unapproved behavior")
    if "SENTINEL_SENSOR_KEYS=" in content:
        raise ValueError("Secret material must not be placed in the unit")


def _trusted_root_file(path: Path) -> None:
    if not path.is_absolute():
        raise ValueError("Absolute configuration path required")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("Service configuration must be root-owned and not writable by group/others")


def inspect_deployment(*, source: Path, state_dir: Path, key_file: Path,
                       config_file: Path, unit_file: Path, environ: Mapping[str, str] | None = None,
                       fixture: bool = False) -> dict:
    """Return bounded, secret-free checks. No directories, state files or sockets are created."""
    environ = os.environ if environ is None else environ
    checks: list[dict[str, str]] = []

    def check(name: str, operation) -> None:
        try:
            operation()
        except (OSError, ValueError, CollectorError, KeyError):
            # Only an authored, non-sensitive reason; never echo the exception,
            # whose operating-system path or contents may identify host details.
            checks.append({"id": name, "result": "fail"})
        else:
            checks.append({"id": name, "result": "pass"})

    def linux() -> None:
        if platform.system() != "Linux":
            raise ValueError("Not Linux")
    check("linux_platform", linux)

    def account() -> None:
        if pwd.getpwnam("sentinel-sensor").pw_uid != os.geteuid() or os.geteuid() == 0:
            raise ValueError("Not dedicated unprivileged service account")
    if fixture:
        checks.append({"id": "service_account", "result": "not_verified"})
    else:
        check("service_account", account)

    def secret() -> None:
        if environ.get("SENTINEL_SENSOR_KEYS", "").strip():
            raise ValueError("Conflicting environment-based secret")
        read_private_sensor_key(key_file)  # Never record or return secret value.
    check("private_signing_key", secret)

    def log() -> None:
        handle, _ = _open_log(source)
        handle.close()  # No log contents read.
    check("readonly_log_access", log)

    def state() -> None:
        if not state_dir.is_absolute():
            raise ValueError("Invalid state path")
        info = state_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("State directory is not private")
        if not os.access(state_dir, os.R_OK | os.W_OK | os.X_OK):
            raise ValueError("State directory cannot be used")
        # Validates an existing cursor without creating one.
        if (state_dir / "ssh-cursor.json").exists() or (state_dir / "ssh-cursor.json").is_symlink():
            _read_state(state_dir / "ssh-cursor.json")
    check("private_cursor_storage", state)

    if fixture:
        checks.append({"id": "root_owned_service_config", "result": "not_verified"})
    else:
        check("root_owned_service_config", lambda: (_trusted_root_file(config_file),
                                                        _trusted_root_file(unit_file)))
    check("strict_metadata", lambda: _config(config_file))
    check("service_unit_contract", lambda: _unit(unit_file, source=source,
                                                   state_dir=state_dir, key_file=key_file,
                                                   config_file=config_file))
    return {
        "schema": "sentinel-linux-preflight-v1",
        "scope": "offline fixture" if fixture else "live-host static preflight",
        "all_checks_passed": all(c["result"] == "pass" for c in checks if c["result"] != "not_verified"),
        "host_certified": False,
        "checks": checks,
        "limitations": ["no systemd boot/restart exercised", "no live event capture exercised",
                        "no credentials, raw logs, or filesystem changes included"],
    }
