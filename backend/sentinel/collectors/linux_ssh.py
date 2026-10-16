"""Minimal read-only SSH authentication failure collector for Linux syslog files.

Supports only explicit local regular files. Sends sanitized authentication-failure
records to the already existing localhost, HMAC-authenticated ingestion API.
It neither collects credentials nor executes enforcement commands.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from datetime import datetime, timezone
from typing import Callable

# Restrict to a complete sshd password/public-key failure message. Do not copy
# usernames, ports, original log lines, or credential guesses into telemetry.
SSH_FAILED = re.compile(
    rb"\bsshd\[\d+\]: Failed (?:password|publickey) for (?:invalid user )?"
    rb"[^\r\n]{1,120}? from (?P<ip>[0-9a-fA-F:.]{3,45}) port \d{1,5}(?:\s|$)"
)
MAX_LOG_LINE = 16384
MAX_PER_POLL = 1000


class CollectorError(RuntimeError):
    """A safe, non-sensitive collector failure."""


def extract_source_ip(line: bytes) -> str | None:
    match = SSH_FAILED.search(line)
    if match is None:
        return None
    try:
        return str(ipaddress.ip_address(match.group("ip").decode("ascii")))
    except (ValueError, UnicodeError):
        return None


def _open_log(path: Path):
    if not path.is_absolute():
        raise CollectorError("Log source must be an absolute path")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise CollectorError("Log source cannot be opened safely") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise CollectorError("Log source must be a regular file not writable by group/others")
        return os.fdopen(fd, "rb"), info
    except Exception:
        os.close(fd)
        raise


def _safe_state_directory(directory: Path):
    if not directory.is_absolute():
        raise CollectorError("Cursor location must be an absolute path")
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise CollectorError("Cursor directory must be private and owned by the collector")


def _read_state(path: Path) -> tuple[int, int, int, str] | None:
    _safe_state_directory(path.parent)
    if not path.exists() and not path.is_symlink():
        return None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise CollectorError("Cursor must be a private regular file")
            raw = stream.read(512)
            if stream.read(1):
                raise CollectorError("Cursor file is oversized")
        state = json.loads(raw)
        if set(state) != {"device", "inode", "offset", "generation"}:
            raise ValueError("Unknown cursor fields")
        values = tuple(state[k] for k in ("device", "inode", "offset"))
        generation = state["generation"]
        if (any(type(value) is not int or value < 0 for value in values) or
                not isinstance(generation, str) or not re.fullmatch(r"[a-f0-9]{32}", generation)):
            raise ValueError("Invalid cursor values")
        return (*values, generation)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise CollectorError("Cursor is invalid or cannot be read safely") from exc


def _save_state(path: Path, device: int, inode: int, offset: int, generation: str) -> None:
    # Atomic replace avoids half-written checkpoints. Directory must remain private.
    _safe_state_directory(path.parent)
    if path.is_symlink():
        raise CollectorError("Cursor path may not be a symlink")
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(temp, flags, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(json.dumps({"device": device, "inode": inode, "offset": offset, "generation": generation}).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        # Best effort filesystem durability of the rename itself.
        if hasattr(os, "O_DIRECTORY"):
            dirfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def _nonce(key: str, device: int, inode: int, offset: int, generation: str) -> str:
    # Deterministic position-bound nonce ensures retries cannot create fresh
    # duplicate events when an ACK was received but checkpoint write failed.
    return hmac.new(key.encode(), f"ssh-log:v1:{device}:{inode}:{generation}:{offset}".encode(), hashlib.sha256).hexdigest()[:32]


def process_file(*, source: Path, state_path: Path, asset_id: str, sensor_key: str,
                 send: Callable[[bytes, str], None], max_lines: int = MAX_PER_POLL,
                 start_at_end: bool = False) -> tuple[int, int]:
    """Process a bounded chunk. Returns (lines inspected, events sent/confirmed).

    `send` must raise on transport/server failure, and may treat HTTP 409 on a
    position-bound nonce as already accepted. Cursor advances only on success.
    """
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", asset_id):
        raise CollectorError("Invalid asset ID")
    if len(sensor_key) < 32:
        raise CollectorError("Invalid sensor secret")
    if not 1 <= max_lines <= MAX_PER_POLL:
        raise CollectorError("Invalid per-poll line limit")
    previous = _read_state(state_path)
    stream, info = _open_log(source)
    with stream:
        device, inode = info.st_dev, info.st_ino
        if previous and previous[:2] == (device, inode) and previous[2] <= info.st_size:
            offset, generation = previous[2], previous[3]
        else:
            offset, generation = (info.st_size if previous is None and start_at_end else 0), secrets.token_hex(16)
            # Persist generation before any submission: retrying after a crash
            # must reuse the same nonce. A truncated file gets a new generation.
            _save_state(state_path, device, inode, offset, generation)
        stream.seek(offset)
        seen = sent = 0
        last_completed = offset
        while seen < max_lines:
            start = stream.tell()
            line = stream.readline(MAX_LOG_LINE + 1)
            if not line:
                break
            if not line.endswith(b"\n") and len(line) <= MAX_LOG_LINE:
                # Keep incomplete last line for next poll.
                break
            if len(line) > MAX_LOG_LINE:
                raise CollectorError("Oversized log line; manual inspection required")
            seen += 1
            source_ip = extract_source_ip(line)
            if source_ip:
                data = json.dumps({
                    "asset_id": asset_id, "category": "authentication",
                    "action": "auth_failure", "source_ip": source_ip,
                    # Syslog-style lines lack trustworthy year/timezone; timestamp
                    # is *collection time*, never misrepresented as source time.
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                }, separators=(",", ":")).encode()
                send(data, _nonce(sensor_key, device, inode, start, generation))
                sent += 1
                _save_state(state_path, device, inode, stream.tell(), generation)
            last_completed = stream.tell()
        # Non-matching lines are checkpointed too; no payloads are transmitted.
        _save_state(state_path, device, inode, last_completed, generation)
        return seen, sent


def send_signed(*, raw: bytes, nonce: str, sensor_id: str, sensor_key: str, host: str, port: int) -> None:
    # Literal loopback only; no environment proxies, DNS, or HTTP redirects.
    if host not in {"127.0.0.1", "::1"} or not (1 <= port <= 65535):
        raise CollectorError("Collector may send only to literal loopback")
    stamp = str(int(time.time()))
    canonical = f"{sensor_id}\n{stamp}\n{nonce}\n{hashlib.sha256(raw).hexdigest()}".encode()
    signature = hmac.new(sensor_key.encode(), canonical, hashlib.sha256).hexdigest()
    connection = http.client.HTTPConnection(host, port, timeout=8)
    try:
        connection.request("POST", "/api/v1/events", body=raw, headers={
            "Content-Type": "application/json", "X-Sentinel-Sensor": sensor_id,
            "X-Sentinel-Timestamp": stamp, "X-Sentinel-Nonce": nonce,
            "X-Sentinel-Signature": signature,
        })
        response = connection.getresponse()
        response.read(1024)
        if response.status not in (202, 409):
            raise CollectorError(f"Ingestion rejected record (HTTP {response.status})")
    except (OSError, http.client.HTTPException) as exc:
        raise CollectorError("Local ingestion connection failed") from exc
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Linux SSH failure sensor (local API only)")
    parser.add_argument("--source", required=True, type=Path, help="Absolute /var/log/auth.log or /var/log/secure path")
    parser.add_argument("--state", required=True, type=Path, help="Private cursor JSON path in 0700 directory")
    parser.add_argument("--asset", required=True, help="Stable local asset identifier")
    parser.add_argument("--sensor", required=True, help="Sensor id present in SENTINEL_SENSOR_KEYS")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--follow", action="store_true", help="Continue polling; default runs once")
    parser.add_argument("--backfill", action="store_true", help="Opt in to historical records on first run; may create misleading bursts")
    parser.add_argument("--interval", type=float, default=5.0)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", args.sensor):
        parser.error("Invalid sensor identifier")
    if not 1 <= args.interval <= 60 or not 1 <= args.port <= 65535:
        parser.error("Port and interval must be within safe bounds")
    try:
        config = json.loads(os.environ.get("SENTINEL_SENSOR_KEYS", "{}"))
        secret = config.get(args.sensor) if isinstance(config, dict) else None
        if not isinstance(secret, str) or len(secret) < 32:
            raise CollectorError("Configured sensor secret is missing")
        while True:
            count, accepted = process_file(
                source=args.source, state_path=args.state, asset_id=args.asset,
                sensor_key=secret, start_at_end=not args.backfill,
                send=lambda raw, nonce: send_signed(
                    raw=raw, nonce=nonce, sensor_id=args.sensor, sensor_key=secret,
                    host="127.0.0.1", port=args.port))
            print(f"inspected={count} normalized_auth_failures={accepted}", flush=True)
            if not args.follow:
                return 0
            time.sleep(args.interval)
    except (CollectorError, OSError) as exc:
        print(f"Collector stopped safely: {exc}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
