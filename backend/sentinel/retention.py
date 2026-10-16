"""Conservative local maintenance: prune expired replay nonces, never case evidence.

The sensor timestamp signature window is +/-120s; the shortest supported nonce
window is 24h. Applying requires a verified, newly created SQLite backup and a
valid HMAC audit chain. There is deliberately no HTTP endpoint or event purge.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import create_engine, delete, func, select, update, event as sa_event
from sqlalchemy.orm import Session

from .audit import append_audit, lock_audit_head, verify_case_decisions, verify_chain, verify_event_evidence
from .backup import create_backup
from .database import verify_schema
from .models import AlertEvidence, AuditHead, AuditRecord, SecurityEvent, SensorNonce

MIN_DAYS = 1
MAX_DAYS = 365


def _engine(source: Path):
    source = Path(source)
    if source.is_symlink() or not source.is_file():
        raise ValueError('Source must be an existing regular SQLite file, not a symlink')
    engine = create_engine(f'sqlite:///{source.resolve()}', connect_args={'check_same_thread': False})

    @sa_event.listens_for(engine, 'connect')
    def enable_fk(connection, _):
        cursor = connection.cursor()
        cursor.execute('PRAGMA foreign_keys=ON')
        cursor.close()
    return engine


def nonce_retention(source: Path, audit_key: str, *, days: int = 7,
                    apply: bool = False, backup_dir: Path | None = None,
                    now: datetime | None = None) -> dict:
    """Return non-sensitive counts; changes are all-or-nothing and backup-gated.

    Preview is non-destructive and useful for sizing. In apply mode the source
    must remain operationally quiescent; an audit-head comparison rejects writes
    between the verified backup snapshot and lock acquisition. It is not an
    assurance of power-loss durability or an off-host backup.
    """
    if type(days) is not int or not MIN_DAYS <= days <= MAX_DAYS:
        raise ValueError('Retention days must be an integer from 1 to 365')
    if len(audit_key) < 32:
        raise ValueError('A strong existing audit key is required')
    if apply and backup_dir is None:
        raise ValueError('Applying retention requires a new verified backup directory')
    if not apply and backup_dir is not None:
        raise ValueError('Backup destination is accepted only with apply=True')
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise ValueError('now must be timezone-aware UTC')
    cutoff = now - timedelta(days=days)
    engine = _engine(Path(source))
    try:
        verify_schema(engine)
        with Session(engine) as session:
            if not verify_chain(session, audit_key) or not verify_case_decisions(session) or not verify_event_evidence(session)[0]:
                raise ValueError('Audit or incident-decision verification failed; no data removed')
            eligible = session.scalar(select(func.count()).select_from(SensorNonce).where(SensorNonce.seen_at < cutoff)) or 0
            total = session.scalar(select(func.count()).select_from(SensorNonce)) or 0
            events = session.scalar(select(func.count()).select_from(SecurityEvent)) or 0
            links = session.scalar(select(func.count()).select_from(AlertEvidence)) or 0
            audit_count = session.scalar(select(func.count()).select_from(AuditRecord)) or 0
            report = {'mode': 'apply' if apply else 'preview', 'days': days,
                      'cutoff_utc': cutoff.isoformat(), 'eligible_nonces': eligible,
                      'nonces_before': total, 'events_preserved': events,
                      'evidence_links_preserved': links, 'audit_records_before': audit_count,
                      'deleted_nonces': 0, 'changed': False,
                      'assurance': 'SQLite authenticated local snapshot; audit chain is not externally immutable'}
            if not apply or not eligible:
                return report
        # Never purge before create_backup completes its integrity verification.
        snapshot = create_backup(Path(source), Path(backup_dir), audit_key)
        with Session(engine) as session:
            head = lock_audit_head(session)
            # Refuse to act if the backup no longer represents the current audited state.
            if (head.entry_count != snapshot['audit_entries'] or
                    head.last_hash != snapshot['audit_head'] or
                    not verify_chain(session, audit_key) or
                    not verify_case_decisions(session) or
                    not verify_event_evidence(session)[0]):
                session.rollback()
                raise ValueError('Database changed or integrity failed after backup; no nonces removed')
            count = session.execute(delete(SensorNonce).where(SensorNonce.seen_at < cutoff)).rowcount
            if count:
                append_audit(session, audit_key, actor='system:local-retention',
                             action='replay-nonces.pruned',
                             resource=f'cutoff:{cutoff.isoformat()};count:{count}')
            session.commit()
            report['deleted_nonces'] = count
            report['changed'] = bool(count)
            return report
    finally:
        engine.dispose()
