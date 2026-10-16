"""Read-only, loopback-only operational coverage probe.

Only authenticated, server-observed contact is measured. Never interpret a
healthy connection as attestation of the protected host or complete logs.
"""
from __future__ import annotations

from dataclasses import dataclass
import http.client
import json
import os
from pathlib import Path
import re
import stat

MAX_REPLY_BYTES = 128 * 1024
MAX_SENSORS = 2048
VALID_STATES = frozenset({"healthy", "stale", "never_seen"})


class CoverageProbeError(RuntimeError):
    """Non-sensitive operational error."""


@dataclass(frozen=True)
class CoverageAssessment:
    configured: int
    healthy: int
    stale: int
    never_seen: int
    explicitly_enrolled: int
    gaps: tuple[str, ...]

    @property
    def clear(self) -> bool:
        return self.configured > 0 and not self.gaps

    def summary(self) -> dict[str, int | bool]:
        return {
            "configured": self.configured,
            "healthy": self.healthy,
            "stale": self.stale,
            "never_seen": self.never_seen,
            "explicitly_enrolled": self.explicitly_enrolled,
            "coverage_clear": self.clear,
        }


def assess(payload: object) -> CoverageAssessment:
    """Fail closed if any sensor or declared summary cannot be reconciled."""
    if not isinstance(payload, dict) or not isinstance(payload.get("sensors"), list):
        raise CoverageProbeError("Invalid sensor coverage response")
    sensors = payload["sensors"]
    if not 1 <= len(sensors) <= MAX_SENSORS:
        raise CoverageProbeError("Coverage inventory is empty or oversized")
    if not isinstance(payload.get("summary"), dict):
        raise CoverageProbeError("Coverage summary is missing")
    totals = {"healthy": 0, "stale": 0, "never_seen": 0}
    gaps: list[str] = []
    ids: set[str] = set()
    explicit = 0
    for entry in sensors:
        if not isinstance(entry, dict):
            raise CoverageProbeError("Invalid sensor entry")
        identifier, state, mode = entry.get("sensor_id"), entry.get("status"), entry.get("binding_mode")
        if (not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identifier)
                or identifier in ids or state not in VALID_STATES or mode not in {"explicit", "first_contact"}):
            raise CoverageProbeError("Invalid sensor identity or coverage state")
        ids.add(identifier)
        totals[state] += 1
        if mode == "explicit":
            explicit += 1
        if state != "healthy":
            gaps.append(identifier)
    expected = payload["summary"]
    expected_values = {
        "configured": len(sensors), "healthy": totals["healthy"],
        "gaps": len(gaps), "explicitly_enrolled": explicit,
    }
    if any(type(expected.get(k)) is not int or expected[k] != v for k, v in expected_values.items()):
        raise CoverageProbeError("Coverage summary does not match sensor inventory")
    return CoverageAssessment(
        configured=len(sensors), healthy=totals["healthy"], stale=totals["stale"],
        never_seen=totals["never_seen"], explicitly_enrolled=explicit, gaps=tuple(sorted(gaps)))


def read_private_token(path: Path) -> str:
    """Load viewer-scoped bearer token from an owned private regular file."""
    if not path.is_absolute():
        raise CoverageProbeError("Token file path must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as file:
            info = os.fstat(file.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077):
                raise CoverageProbeError("Token file must be a private, user-owned regular file")
            raw = file.read(513)
    except OSError as exc:
        raise CoverageProbeError("Cannot open token file securely") from exc
    if len(raw) > 512:
        raise CoverageProbeError("Token file is oversized")
    try:
        token = raw.decode("ascii").removesuffix("\n")
    except UnicodeError as exc:
        raise CoverageProbeError("Invalid token encoding") from exc
    if not 32 <= len(token) <= 256 or not re.fullmatch(r"[A-Za-z0-9_~.\-]+", token):
        raise CoverageProbeError("Invalid token file contents")
    return token


def fetch_coverage(*, port: int, token: str, timeout: float = 5.0) -> CoverageAssessment:
    """Fixed loopback transport; no user-selectable URL, DNS, redirects or proxies."""
    if not 1 <= port <= 65535 or not 0.5 <= timeout <= 10.0:
        raise CoverageProbeError("Invalid local probe configuration")
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("GET", "/api/v1/sensors", headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
            "Cache-Control": "no-store",
        })
        response = conn.getresponse()
        if response.status != 200:
            raise CoverageProbeError("Coverage API unavailable or access denied")
        if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise CoverageProbeError("Unexpected coverage response type")
        raw = response.read(MAX_REPLY_BYTES + 1)
        if len(raw) > MAX_REPLY_BYTES:
            raise CoverageProbeError("Coverage response is oversized")
        try:
            document = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise CoverageProbeError("Invalid coverage JSON response") from exc
        return assess(document)
    except (OSError, http.client.HTTPException, TimeoutError) as exc:
        raise CoverageProbeError("Local coverage probe connection failed") from exc
    finally:
        conn.close()
