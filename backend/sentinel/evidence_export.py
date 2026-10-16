"""Offline, non-destructive, HMAC-sealed SQLite event-evidence export.

This is a point-in-time *copy* of normalized event rows and their linked case IDs,
not a deletion, complete incident archive, immutable external anchor, or legal
chain-of-custody certification. Data can include sensitive source IP addresses.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from .backup import _private_parent, _private_write, _regular_file, _sync_directory, create_backup
from .database import HEAD_REVISION
from .models import AlertEvidence, SecurityEvent

FORMAT = "sentinel-event-evidence-export-v1"
DATA_FILE = "events.jsonl"
MANIFEST_FILE = "manifest.json"
MAX_EVENTS = 10000
MAX_BYTES = 64 * 1024 * 1024


def _canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _seal(key: str, fields: dict) -> str:
    # Domain-separated from audit-record/backup signatures using the same
    # operator-supplied secret; neither secret nor raw credentials are exported.
    domain_key = hmac.new(key.encode(), b"sentinel-event-evidence-export-v1", hashlib.sha256).digest()
    return hmac.new(domain_key, _canonical(fields), hashlib.sha256).hexdigest()


def _utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)  # SQLite drops timezone offsets.
    return value.astimezone(timezone.utc).isoformat()


def _validate(source: Path, destination: Path, key: str, older_than_days: int, max_events: int) -> None:
    if len(key) < 32:
        raise ValueError("A strong existing audit key is required")
    if type(older_than_days) is not int or not 1 <= older_than_days <= 3650:
        raise ValueError("older_than_days must be an integer from 1 to 3650")
    if type(max_events) is not int or not 1 <= max_events <= MAX_EVENTS:
        raise ValueError("max_events must be an integer from 1 to 10000")
    _regular_file(source)
    _private_parent(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Export directory already exists; refusing overwrite")


def export_event_evidence(source: Path, destination: Path, audit_key: str, *,
                          older_than_days: int = 30, max_events: int = 1000,
                          now: datetime | None = None) -> dict:
    """Seal a bounded export from an independently audited SQLite snapshot.

    The original DB is unchanged. Refuse a partial selection when eligible
    events exceed the operator's explicit bound; no silent truncation.
    """
    source, destination = Path(source), Path(destination)
    _validate(source, destination, audit_key, older_than_days, max_events)
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise ValueError("now must be timezone-aware UTC")
    cutoff = now - timedelta(days=older_than_days)

    # SQLite online backup supplies a consistent point-in-time view including
    # WAL data. It must pass schema, audit-chain and case-decision verification.
    with tempfile.TemporaryDirectory(prefix="sentinel-export-snapshot-", dir=destination.parent) as temp:
        snapshot_dir = Path(temp) / "backup"
        metadata = create_backup(source, snapshot_dir, audit_key)
        engine = create_engine(f"sqlite:///{snapshot_dir / 'snapshot.sqlite3'}")
        try:
            with Session(engine) as session:
                events = session.scalars(
                    select(SecurityEvent).where(SecurityEvent.received_at < cutoff)
                    .order_by(SecurityEvent.received_at, SecurityEvent.id)
                    .limit(max_events + 1)
                ).all()
                if len(events) > max_events:
                    raise ValueError("Eligible events exceed max_events; raise the explicit bound or narrow the selection")
                event_ids = [row.id for row in events]
                links = session.scalars(
                    select(AlertEvidence).where(AlertEvidence.event_id.in_(event_ids))
                    .order_by(AlertEvidence.event_id, AlertEvidence.alert_id)
                ).all() if event_ids else []
                by_event: dict[str, list[str]] = {}
                for link in links:
                    by_event.setdefault(link.event_id, []).append(link.alert_id)
                records = [{
                    "event_id": row.id,
                    "sensor_id": row.sensor_id,
                    "asset_id": row.asset_id,
                    "category": row.category,
                    "action": row.action,
                    "source_ip": row.source_ip,
                    "observed_at": _utc(row.observed_at),
                    "received_at": _utc(row.received_at),
                    "linked_alert_ids": sorted(set(by_event.get(row.id, []))),
                } for row in events]
        finally:
            engine.dispose()

        payload = b"".join(_canonical(record) + b"\n" for record in records)
        if len(payload) > MAX_BYTES:
            raise ValueError("Evidence bundle exceeds safe size limit")
        fields = {
            "format": FORMAT,
            "schema_revision": HEAD_REVISION,
            "snapshot_audit_head": metadata["audit_head"],
            "snapshot_audit_entries": metadata["audit_entries"],
            "exported_at": _utc(now),
            "received_before_utc": _utc(cutoff),
            "events_count": len(records),
            "evidence_links_count": sum(len(record["linked_alert_ids"]) for record in records),
            "events_sha256": hashlib.sha256(payload).hexdigest(),
            "scope": "normalized-events-and-linked-alert-ids-only;source-unchanged",
        }
        manifest = _canonical({"data": fields, "hmac_sha256": _seal(audit_key, fields)}) + b"\n"
        destination.mkdir(mode=0o700)
        try:
            _private_write(destination / DATA_FILE, payload)
            _private_write(destination / MANIFEST_FILE, manifest)
            _sync_directory(destination)
            _sync_directory(destination.parent)
        except BaseException:
            # Remove only files made inside this newly created private directory.
            for child in (destination / DATA_FILE, destination / MANIFEST_FILE):
                child.unlink(missing_ok=True)
            destination.rmdir()
            raise
    return fields


def verify_event_export(directory: Path, audit_key: str) -> dict:
    """Verify a sealed bundle; original DB is not required for verification."""
    directory = Path(directory)
    if len(audit_key) < 32:
        raise ValueError("A strong existing audit key is required")
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Export must be an existing real directory")
    if os.name == "posix" and directory.stat().st_mode & 0o077:
        raise ValueError("Evidence directory must be private")
    manifest_path, data_path = directory / MANIFEST_FILE, directory / DATA_FILE
    _regular_file(manifest_path)
    _regular_file(data_path)
    if manifest_path.stat().st_size > 8192 or data_path.stat().st_size > MAX_BYTES:
        raise ValueError("Evidence bundle exceeds size limits")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Invalid evidence manifest") from exc
    if not isinstance(manifest, dict) or set(manifest) != {"data", "hmac_sha256"}:
        raise ValueError("Invalid evidence manifest shape")
    fields, sig = manifest["data"], manifest["hmac_sha256"]
    expected = {"format", "schema_revision", "snapshot_audit_head", "snapshot_audit_entries",
                "exported_at", "received_before_utc", "events_count", "evidence_links_count",
                "events_sha256", "scope"}
    if (not isinstance(fields, dict) or set(fields) != expected or
            not isinstance(sig, str) or len(sig) != 64):
        raise ValueError("Invalid evidence manifest fields")
    if not hmac.compare_digest(_seal(audit_key, fields), sig):
        raise ValueError("Evidence manifest authentication failed")
    if fields["format"] != FORMAT or fields["schema_revision"] != HEAD_REVISION:
        raise ValueError("Unsupported evidence format or schema")
    digest, count, link_count = hashlib.sha256(), 0, 0
    with data_path.open("rb") as stream:
        for raw in stream:
            digest.update(raw)
            count += 1
            if count > MAX_EVENTS:
                raise ValueError("Evidence event count exceeds bound")
            try:
                item = json.loads(raw)
            except (ValueError, UnicodeError) as exc:
                raise ValueError("Invalid JSONL evidence") from exc
            if not isinstance(item, dict) or not isinstance(item.get("linked_alert_ids"), list):
                raise ValueError("Invalid event evidence shape")
            link_count += len(item["linked_alert_ids"])
    if (digest.hexdigest() != fields["events_sha256"] or count != fields["events_count"] or
            link_count != fields["evidence_links_count"]):
        raise ValueError("Event evidence checksum or counts mismatch")
    return fields
