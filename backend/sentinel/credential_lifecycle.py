"""Offline local administration of database-backed operator credentials."""
import hashlib
import os
from pathlib import Path
import re
import secrets
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from .audit import append_audit, lock_audit_head, verify_chain
from .database import verify_schema
from .models import OperatorCredential, utcnow

ROLES = frozenset(("viewer", "analyst", "admin"))

def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

def _check_id(value: str):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{2,63}", value):
        raise ValueError("Invalid operator ID")

def _check_ttl(days: int):
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 90:
        raise ValueError("Credential validity must be 1..90 days")

def _ready(url: str, audit_key: str):
    if len(audit_key) < 32 or not url.startswith(("sqlite:", "postgresql+psycopg:")):
        raise ValueError("A valid database URL and audit key are required")
    engine = create_engine(url, pool_pre_ping=True)
    try:
        verify_schema(engine)
    except BaseException:
        engine.dispose()
        raise
    return engine

def _write_token_file(path: Path, token: str):
    if path.is_symlink():
        raise ValueError("Credential output must not be a symbolic link")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as out:
            out.write(token + "\n")
            out.flush()
            os.fsync(out.fileno())
        os.chmod(path, 0o600)
    except BaseException:
        path.unlink(missing_ok=True)
        raise

def _active_admins(session: Session, now: datetime) -> int:
    return len(session.scalars(select(OperatorCredential.id).where(
        OperatorCredential.role == "admin",
        OperatorCredential.revoked_at.is_(None),
        OperatorCredential.expires_at > now,
    )).all())

def create_or_rotate(url: str, audit_key: str, *, operator_id: str,
                     role: str | None, valid_days: int, secret_file: Path,
                     previous_id: int | None = None) -> int:
    """Token is written once to a private file; rotation is one DB transaction."""
    _check_id(operator_id)
    _check_ttl(valid_days)
    if previous_id is None and role not in ROLES:
        raise ValueError("Invalid operator role")
    if previous_id is not None and (isinstance(previous_id, bool) or not isinstance(previous_id, int) or previous_id < 1):
        raise ValueError("Invalid credential ID")
    if previous_id is not None and role is not None:
        raise ValueError("Rotation cannot change operator role")
    secret_file = Path(secret_file)
    engine = _ready(url, audit_key)
    token = secrets.token_urlsafe(48)
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    file_created = False
    try:
        with Session(engine) as session:
            lock_audit_head(session)
            if not verify_chain(session, audit_key):
                raise RuntimeError("Audit integrity failed; refusing credential change")
            now = utcnow()
            if previous_id is not None:
                old = session.get(OperatorCredential, previous_id)
                if old is None or old.operator_id != operator_id or old.revoked_at is not None or _as_utc(old.expires_at) <= now:
                    raise ValueError("Credential to rotate is not active for this operator")
                role = old.role
            else:
                old = None
            _write_token_file(secret_file, token)
            file_created = True
            new = OperatorCredential(
                operator_id=operator_id, role=role, token_sha256=digest,
                created_at=now, expires_at=now + timedelta(days=valid_days), revoked_at=None)
            session.add(new)
            session.flush()
            if old is not None:
                old.revoked_at = now
                append_audit(session, audit_key, actor="local:credential-admin",
                             action="credential.rotated",
                             resource=f"old:{old.id};new:{new.id};operator:{operator_id}")
            else:
                append_audit(session, audit_key, actor="local:credential-admin",
                             action="credential.enrolled",
                             resource=f"credential:{new.id};operator:{operator_id};role:{role}")
            session.commit()
            return new.id
    except BaseException:
        if file_created:
            secret_file.unlink(missing_ok=True)
        raise
    finally:
        engine.dispose()

def revoke_credential(url: str, audit_key: str, credential_id: int) -> None:
    if isinstance(credential_id, bool) or not isinstance(credential_id, int) or credential_id < 1:
        raise ValueError("Invalid credential ID")
    engine = _ready(url, audit_key)
    try:
        with Session(engine) as session:
            lock_audit_head(session)
            if not verify_chain(session, audit_key):
                raise RuntimeError("Audit integrity failed; refusing credential change")
            now = utcnow()
            row = session.get(OperatorCredential, credential_id)
            if row is None or row.revoked_at is not None:
                raise ValueError("Credential does not exist or is already revoked")
            if row.role == "admin" and _as_utc(row.expires_at) > now and _active_admins(session, now) <= 1:
                raise ValueError("Cannot revoke the last active admin; rotate or enroll a replacement first")
            row.revoked_at = now
            append_audit(session, audit_key, actor="local:credential-admin",
                         action="credential.revoked",
                         resource=f"credential:{credential_id};operator:{row.operator_id}")
            session.commit()
    finally:
        engine.dispose()

def list_credentials(url: str, audit_key: str) -> list[dict]:
    engine = _ready(url, audit_key)
    try:
        with Session(engine) as session:
            now = utcnow()
            result = []
            for row in session.scalars(select(OperatorCredential).order_by(OperatorCredential.id)):
                expiry = _as_utc(row.expires_at)
                status = "revoked" if row.revoked_at else "expired" if expiry <= now else "active"
                result.append({"id": row.id, "operator_id": row.operator_id,
                               "role": row.role, "expires_at": expiry.isoformat(),
                               "status": status})
            return result
    finally:
        engine.dispose()
