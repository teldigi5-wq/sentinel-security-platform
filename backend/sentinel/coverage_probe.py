"""Read-only, loopback-only operational coverage probe.

Exit-code monitoring must fail closed on malformed coverage responses. The probe
reports server-observed contact only; it cannot attest that a host is protected.
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
    """Non-sensitive operator-facing failure."""


@dataclass(frozen=True)
class CoverageAssessment:
    configured: int
    healthy: int
    stale: int
    never_seen: int
    explicitly_enrolled: int
    gaps: tuple[str, ...]
    sensor_states: tuple[tuple[str, str, str], ...] = ()
    sensor_activity: tuple[tuple[str, int, int], ...] = ()

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
    """Do not trust a remote summary; recompute state from individual sensors."""
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
    states: list[tuple[str, str, str]] = []
    activity: list[tuple[str, int, int]] = []
    for entry in sensors:
        if not isinstance(entry, dict):
            raise CoverageProbeError("Invalid sensor entry")
        identifier, state, mode = entry.get("sensor_id"), entry.get("status"), entry.get("binding_mode")
        if (not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identifier)
                or identifier in ids or not isinstance(state, str) or state not in VALID_STATES
                or not isinstance(mode, str) or mode not in {"explicit", "first_contact"}):
            raise CoverageProbeError("Invalid sensor identity or coverage state")
        ids.add(identifier)
        states.append((identifier, state, mode))
        if "event_count" in entry or "heartbeat_count" in entry:
            events, beats = entry.get("event_count"), entry.get("heartbeat_count")
            if (type(events) is not int or type(beats) is not int
                    or not 0 <= events <= 2**63 - 1 or not 0 <= beats <= 2**63 - 1):
                raise CoverageProbeError("Invalid sensor activity counters")
            activity.append((identifier, events, beats))
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
        never_seen=totals["never_seen"], explicitly_enrolled=explicit, gaps=tuple(sorted(gaps)),
        sensor_states=tuple(sorted(states)), sensor_activity=tuple(sorted(activity)))


def read_private_token(path: Path) -> str:
    """Load a viewer/analyst token without using command-line arguments or logging it."""
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
    """Fixed local destination; no URL override, DNS, proxy, redirect or remote host."""
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
