"""Sequential HMAC-linked audit records. See documented single-writer limitations."""
import hashlib
import hmac
import json
import re
from datetime import timezone
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from .models import Alert, AlertDecision, AuditHead, AuditRecord, SecurityEvent, utcnow


def _time_key(at):
    # SQLite drops timezone data; canonicalize SQLite and PostgreSQL representations identically.
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    return at.astimezone(timezone.utc).isoformat()


def _digest(key: str, at: str, actor: str, action: str, resource: str, previous: str) -> str:
    message = "\x1f".join((at, actor, action, resource, previous)).encode()
    return hmac.new(key.encode(), message, hashlib.sha256).hexdigest()


def lock_audit_head(session: Session) -> AuditHead:
    """Acquire the single writer lock *before* reading or mutating event and case state.

    PostgreSQL: SELECT FOR UPDATE holds until commit/rollback.
    SQLite: no-op UPDATE takes the database write lock before dependent reads.
    """
    if session.info.get("sentinel_audit_locked"):
        return session.info["sentinel_audit_locked"]
    if session.get_bind().dialect.name == "sqlite":
        changed = session.execute(update(AuditHead).where(AuditHead.id == 1).values(
            entry_count=AuditHead.entry_count)).rowcount
        if changed != 1:
            raise RuntimeError("Audit head missing; database schema is not initialized")
        head = session.get(AuditHead, 1, populate_existing=True)
    else:
        head = session.scalar(select(AuditHead).where(AuditHead.id == 1).with_for_update())
    if head is None:
        raise RuntimeError("Audit head missing; database schema is not initialized")
    session.info["sentinel_audit_locked"] = head
    return head


def append_audit(session: Session, key: str, *, actor: str, action: str, resource: str) -> None:
    head = lock_audit_head(session)
    at = utcnow()
    digest = _digest(key, _time_key(at), actor, action, resource, head.last_hash)
    session.add(AuditRecord(at=at, actor=actor, action=action, resource=resource,
                            previous_hash=head.last_hash, entry_hash=digest))
    head.last_hash = digest
    head.entry_count += 1
    session.flush()


def verify_chain(session: Session, key: str) -> bool:
    previous = "0" * 64
    count = 0
    for record in session.scalars(select(AuditRecord).order_by(AuditRecord.id)):
        if record.previous_hash != previous or not hmac.compare_digest(
            record.entry_hash, _digest(key, _time_key(record.at), record.actor, record.action, record.resource, previous)
        ):
            return False
        previous = record.entry_hash
        count += 1
    head = session.get(AuditHead, 1)
    return head is not None and head.last_hash == previous and head.entry_count == count


# v0.22 audit resource encoding. The digest binds the normalized, persisted
# row, not just the HTTP submission, including its server-assigned receipt time.
EVENT_ANCHOR_PREFIX = "event:v1:"
EVENT_ANCHOR_RE = re.compile(r"^event:v1:([0-9a-f-]{36}):([0-9a-f]{64})$")


def event_digest(row: SecurityEvent) -> str:
    """Stable JSON framing across SQLite/PostgreSQL UTC DateTime round trips."""
    fields = ["sentinel-event-v1", row.id, row.sensor_id, row.asset_id,
              row.category, row.action, row.source_ip,
              _time_key(row.observed_at), _time_key(row.received_at)]
    canonical = json.dumps(fields, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def verify_event_evidence(session: Session) -> tuple[bool, int]:
    """Cross-check persisted event rows against signed audit resources.

    Pre-v0.22 resources contained only the event ID. Their presence is counted
    as legacy/unanchored, never reported as payload-verified. Missing rows,
    duplicate records, malformed hashes, or changed v1 fields fail validation.
    This does not prove external immutability or the original sensor's honesty.
    """
    events = {event.id: event for event in session.scalars(select(SecurityEvent))}
    audited = session.scalars(select(AuditRecord).where(
        AuditRecord.action == "event.ingested").order_by(AuditRecord.id)).all()
    if len(events) != len(audited):
        return False, 0
    seen: set[str] = set()
    legacy_count = 0
    for record in audited:
        match = EVENT_ANCHOR_RE.fullmatch(record.resource)
        if match is not None:
            event_id, claimed_digest = match.groups()
            event = events.get(event_id)
            if event is None or record.actor != f"sensor:{event.sensor_id}" or not hmac.compare_digest(
                claimed_digest, event_digest(event)
            ):
                return False, legacy_count
        else:
            # Legacy IDs have no separators; never allow a malformed v1 marker
            # to be silently downgraded to the legacy (unanchored) form.
            event_id = record.resource
            if ":" in event_id or event_id not in events:
                return False, legacy_count
            legacy_count += 1
        if event_id in seen:
            return False, legacy_count
        seen.add(event_id)
    return True, legacy_count


def decision_digest(row: AlertDecision) -> str:
    """Bind case decision contents to the signed append-only audit chain."""
    values = (str(row.id), row.alert_id, row.previous_state, row.new_state,
              row.reason, row.actor, _time_key(row.decided_at))
    return hashlib.sha256("\x1f".join(values).encode()).hexdigest()


def verify_case_decisions(session: Session) -> bool:
    """Detect altered/deleted decisions or unsanctioned changes to alert states."""
    audit_rows = session.scalars(select(AuditRecord).where(
        AuditRecord.action == "alert.transition").order_by(AuditRecord.id)).all()
    decisions = session.scalars(select(AlertDecision).order_by(AlertDecision.id)).all()
    if len(audit_rows) != len(decisions):
        return False
    current: dict[str, str] = {}
    for audit, row in zip(audit_rows, decisions):
        if audit.resource != f"decision:{row.id}:{decision_digest(row)}":
            return False
        before = current.get(row.alert_id, "open")
        if row.previous_state != before:
            return False
        current[row.alert_id] = row.new_state
    for alert in session.scalars(select(Alert)):
        if alert.state != current.get(alert.id, "open"):
            return False
    return True
