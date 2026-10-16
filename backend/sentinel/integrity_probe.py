"""Conservative runtime evidence-integrity probe using only the loopback API.

The probe deliberately does not receive an admin key or the audit HMAC secret.
It distinguishes authenticated failure/degradation from network/response unknown.
It does not attest sensor coverage, Linux service identity, or host security.
"""
from __future__ import annotations

from dataclasses import dataclass
import http.client
import json

MAX_REPLY_BYTES = 4096
ASSURANCE = "Local DB audit and event verification only; not external immutability or host certification"


class IntegrityProbeError(RuntimeError):
    """Non-sensitive, actionable failure category."""


@dataclass(frozen=True)
class IntegrityAssessment:
    state: str
    valid: bool
    has_events: bool

    @property
    def clear(self) -> bool:
        return self.state == "anchored" and self.valid and self.has_events

    def summary(self) -> dict[str, bool | str]:
        return {"evidence_state": self.state, "integrity_clear": self.clear,
                "has_events": self.has_events, "host_certified": False}


def assess(document: object) -> IntegrityAssessment:
    if not isinstance(document, dict) or set(document) != {"state", "valid", "has_events", "assurance"}:
        raise IntegrityProbeError("Invalid evidence status response")
    state, valid, has_events = document["state"], document["valid"], document["has_events"]
    if (not isinstance(state, str) or state not in {"anchored", "partial_legacy", "integrity_failed", "empty"}
            or type(valid) is not bool or type(has_events) is not bool
            or document["assurance"] != ASSURANCE):
        raise IntegrityProbeError("Invalid evidence status fields")
    if ((state == "anchored" and (not valid or not has_events))
            or (state == "partial_legacy" and (not valid or not has_events))
            or (state == "integrity_failed" and valid)
            or (state == "empty" and (not valid or has_events))):
        raise IntegrityProbeError("Contradictory evidence status")
    return IntegrityAssessment(state=state, valid=valid, has_events=has_events)


def fetch_integrity(*, port: int, token: str, timeout: float = 5.0) -> IntegrityAssessment:
    """No remote URL, redirects, name resolution, proxy or arbitrary HTTP method."""
    if type(port) is not int or not 1 <= port <= 65535 or not 0.5 <= timeout <= 10.0:
        raise IntegrityProbeError("Invalid local probe configuration")
    if not isinstance(token, str) or not 32 <= len(token) <= 256 or not token.isascii():
        raise IntegrityProbeError("Invalid credential")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request("GET", "/api/v1/audit/status", headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
            "Cache-Control": "no-store",
        })
        reply = connection.getresponse()
        if reply.status != 200:
            raise IntegrityProbeError("Audit status unavailable or access denied")
        if reply.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise IntegrityProbeError("Unexpected audit response format")
        raw = reply.read(MAX_REPLY_BYTES + 1)
        if len(raw) > MAX_REPLY_BYTES:
            raise IntegrityProbeError("Audit response exceeds size limit")
        try:
            document = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise IntegrityProbeError("Invalid audit JSON response") from exc
        return assess(document)
    except (OSError, http.client.HTTPException, TimeoutError) as exc:
        raise IntegrityProbeError("Local evidence probe connection failed") from exc
    finally:
        connection.close()
