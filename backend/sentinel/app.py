"""Sentinel v0.1: authenticated ingestion, deterministic detection, read-only SOC API."""
import hashlib
import hmac
import json
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import create_engine, func, select, update, event as sa_event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from .audit import append_audit, decision_digest, event_digest, lock_audit_head, verify_case_decisions, verify_chain, verify_event_evidence
from .detection import evaluate
from .database import verify_schema
from .models import Alert, AlertDecision, AlertEvidence, AuditRecord, Base, SecurityEvent, SensorNonce, SensorStatus, OperatorCredential, utcnow
from .schemas import IncomingEvent, TriageRequest, SensorHeartbeat
from .settings import OperatorIdentity, Settings, load_settings

def as_utc_iso(value: datetime) -> str:
    """SQLite omits timezone metadata; serialize recorded UTC moments correctly."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


MAX_BODY_BYTES = 8192
MAX_CLOCK_SKEW_SECONDS = 120
SENSOR_STALE_SECONDS = 180

def sensor_state(last_seen: datetime | None, now: datetime) -> str:
    if last_seen is None:
        return "never_seen"
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    age = (now - last_seen).total_seconds()
    # A future timestamp cannot certify health; server clock corruption is a gap.
    return "healthy" if 0 <= age <= SENSOR_STALE_SECONDS else "stale"

def update_sensor_status(session: Session, sensor_id: str, asset_id: str, *, heartbeat: bool,
                         enrolled_asset: str | None = None) -> None:
    # Called only after HMAC verification, within the audit-writer transaction.
    now = utcnow()
    if enrolled_asset is not None and asset_id != enrolled_asset:
        raise HTTPException(status_code=403, detail="Sensor not authorized for this asset")
    status = session.get(SensorStatus, sensor_id)
    # First-contact pinning preserves local compatibility, but must not be
    # mistaken for administrator-approved enrollment. Explicit enrollment
    # is necessary for genuine sensor-to-asset assurance.
    if status is not None and status.asset_id != asset_id:
        raise HTTPException(status_code=403, detail="Sensor not authorized for this asset")
    if status is None:
        status = SensorStatus(sensor_id=sensor_id, asset_id=asset_id, last_seen_at=now,
                              last_event_at=None if heartbeat else now,
                              event_count=0 if heartbeat else 1,
                              heartbeat_count=1 if heartbeat else 0)
        session.add(status)
    else:
        status.last_seen_at = now
        if heartbeat:
            status.heartbeat_count += 1
        else:
            status.last_event_at = now
            status.event_count += 1



def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    if (settings.sensor_assets and (
        set(settings.sensor_assets) != set(settings.sensor_keys)
        or any(not isinstance(asset, str)
                   or not re.fullmatch(r"[a-zA-Z0-9._:-]{1,100}", asset)
                   for asset in settings.sensor_assets.values()))):
        raise RuntimeError("Every configured sensor must have one valid enrolled asset")
    if settings.auth_mode not in ("static", "database"):
        raise RuntimeError("Unsupported operator authentication mode")
    if settings.auth_mode == "database" and (settings.operator_token or settings.operators):
        raise RuntimeError("Database authentication forbids static operator credentials")
    if not settings.database_url.startswith(("sqlite:", "postgresql+psycopg:")):
        raise RuntimeError("Unsupported database scheme")
    engine = create_engine(settings.database_url, pool_pre_ping=True,
                           connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite:") else {})
    if engine.dialect.name == "sqlite":
        @sa_event.listens_for(engine, "connect")
        def enable_foreign_keys(dbapi_conn, connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        verify_schema(engine)
        # Refuse to operate on evidence whose stored state fails authentication.
        # Use one stable read snapshot: PostgreSQL defaults to READ COMMITTED,
        # which could otherwise mix separate concurrent writer transactions.
        with engine.connect() as connection:
            if engine.dialect.name == "postgresql":
                connection = connection.execution_options(isolation_level="REPEATABLE READ")
            with connection.begin():
                with Session(bind=connection) as preflight:
                    event_valid, _legacy_count = verify_event_evidence(preflight)
                    integrity_valid = (verify_chain(preflight, settings.audit_key)
                                       and verify_case_decisions(preflight)
                                       and event_valid)
                    if not integrity_valid:
                        raise RuntimeError("Sentinel evidence integrity check failed at startup; "
                                           "stop the service and investigate or restore a verified backup")
    except Exception:
        engine.dispose()
        raise

    if settings.auth_mode == "database":
        # Deny startup with no active administrator, never fall back to static auth.
        with session_factory() as preflight:
            active_admin = preflight.scalar(select(OperatorCredential.id).where(
                OperatorCredential.role == "admin",
                OperatorCredential.revoked_at.is_(None),
                OperatorCredential.expires_at > utcnow(),
            ).limit(1))
            if active_admin is None:
                engine.dispose()
                raise RuntimeError("Database auth requires an active admin; enroll using the offline credential CLI")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        engine.dispose()

    app = FastAPI(title="Sentinel Security Core", version="0.10.0", docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origins=list(settings.frontend_origins),
                       allow_credentials=False, allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"])

    def get_session():
        with session_factory() as session:
            yield session

    def require_operator(session: Annotated[Session, Depends(get_session)],
                         authorization: Annotated[str | None, Header()] = None) -> OperatorIdentity:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Bearer"})
        token = authorization[7:]
        if not 32 <= len(token) <= 256 or not token.isascii():
            raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Bearer"})
        if settings.auth_mode == "database":
            fingerprint = hashlib.sha256(token.encode()).hexdigest()
            credential = session.scalar(select(OperatorCredential).where(
                OperatorCredential.token_sha256 == fingerprint,
                OperatorCredential.revoked_at.is_(None),
                OperatorCredential.expires_at > utcnow(),
            ))
            if credential is not None:
                return OperatorIdentity(credential.operator_id, credential.role, fingerprint)
        elif settings.operators:
            fingerprint = hashlib.sha256(token.encode()).hexdigest()
            matched = None
            for operator in settings.operators:
                if hmac.compare_digest(fingerprint, operator.token_sha256):
                    matched = operator
            if matched is not None:
                return matched
        elif settings.auth_mode == "static" and settings.operator_token and hmac.compare_digest(token.encode(), settings.operator_token.encode()):
            # Backward compatible *local-only* operation; cannot provide individual attribution.
            return OperatorIdentity("operator", "admin", "")
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Bearer"})

    def require_analyst(operator: Annotated[OperatorIdentity, Depends(require_operator)]) -> OperatorIdentity:
        if operator.role not in ("analyst", "admin"):
            raise HTTPException(status_code=403, detail="Insufficient role")
        return operator

    def require_admin(operator: Annotated[OperatorIdentity, Depends(require_operator)]) -> OperatorIdentity:
        if operator.role != "admin":
            raise HTTPException(status_code=403, detail="Insufficient role")
        return operator

    Operator = Annotated[OperatorIdentity, Depends(require_operator)]
    Analyst = Annotated[OperatorIdentity, Depends(require_analyst)]
    Admin = Annotated[OperatorIdentity, Depends(require_admin)]
    DB = Annotated[Session, Depends(get_session)]

    @app.middleware("http")
    async def no_store_and_limits(request: Request, call_next):
        # Endpoint ingestion enforces the streamed limit; operator API only accepts GET.
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response

    @app.get("/api/v1/health")
    def health():
        return {"status": "ok", "service": "sentinel-core"}

    async def authenticated_sensor(request: Request, session: Session) -> tuple[str, str, bytearray]:
        """Authenticate signed POSTs with the same nonce replay domain for both routes."""
        sensor_id = request.headers.get("X-Sentinel-Sensor", "")
        timestamp = request.headers.get("X-Sentinel-Timestamp", "")
        nonce = request.headers.get("X-Sentinel-Nonce", "")
        signature = request.headers.get("X-Sentinel-Signature", "")
        secret = settings.sensor_keys.get(sensor_id)
        if not secret or not re.fullmatch(r"[0-9]{10}", timestamp) or not re.fullmatch(r"[a-f0-9]{32}", nonce) or not re.fullmatch(r"[a-f0-9]{64}", signature):
            raise HTTPException(status_code=401, detail="Invalid sensor authentication")
        if abs(int(datetime.now(timezone.utc).timestamp()) - int(timestamp)) > MAX_CLOCK_SKEW_SECONDS:
            raise HTTPException(status_code=401, detail="Expired sensor authentication")
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > MAX_BODY_BYTES:
                raise HTTPException(status_code=413, detail="Event body too large")
        canonical = f"{sensor_id}\n{timestamp}\n{nonce}\n{hashlib.sha256(raw).hexdigest()}".encode()
        expected = hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise HTTPException(status_code=401, detail="Invalid sensor authentication")
        return sensor_id, nonce, raw

    @app.post("/api/v1/sensors/heartbeat", status_code=202)
    async def heartbeat(request: Request, session: DB):
        sensor_id, nonce, raw = await authenticated_sensor(request, session)
        try:
            body = SensorHeartbeat.model_validate_json(raw)
        except (ValidationError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="Invalid sensor heartbeat") from exc
        try:
            lock_audit_head(session)
            session.add(SensorNonce(sensor_id=sensor_id, nonce=nonce))
            session.flush()
            update_sensor_status(session, sensor_id, body.asset_id, heartbeat=True,
                                 enrolled_asset=settings.sensor_assets.get(sensor_id))
            append_audit(session, settings.audit_key, actor=f"sensor:{sensor_id}",
                         action="sensor.heartbeat", resource=body.asset_id)
            session.commit()
        except IntegrityError as exc:
            session.rollback()
            raise HTTPException(status_code=409, detail="Duplicate event nonce") from exc
        return {"accepted": True}

    @app.post("/api/v1/events", status_code=202)
    async def ingest(request: Request, session: DB):
        sensor_id, nonce, raw = await authenticated_sensor(request, session)
        try:
            body = IncomingEvent.model_validate_json(raw)
            body.check_pair()
        except (ValidationError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="Invalid security event") from exc
        if not (utcnow() - timedelta(hours=24) <= body.observed_at <= utcnow() + timedelta(minutes=5)):
            raise HTTPException(status_code=422, detail="Event timestamp outside accepted window")
        incoming = SecurityEvent(id=str(uuid.uuid4()), sensor_id=sensor_id, asset_id=body.asset_id,
                                 category=body.category.value, action=body.action.value,
                                 source_ip=body.source_ip, observed_at=body.observed_at)
        try:
            lock_audit_head(session)  # Serialize detection + audit across writers.
            session.add(SensorNonce(sensor_id=sensor_id, nonce=nonce))
            session.add(incoming)
            update_sensor_status(session, sensor_id, body.asset_id, heartbeat=False,
                                 enrolled_asset=settings.sensor_assets.get(sensor_id))
            session.flush()
            alerts = evaluate(session, incoming)
            append_audit(session, settings.audit_key, actor=f"sensor:{sensor_id}",
                         action="event.ingested", resource=f"event:v1:{incoming.id}:{event_digest(incoming)}")
            for alert_id in alerts:
                append_audit(session, settings.audit_key, actor="detection-engine", action="alert.created", resource=alert_id)
            session.commit()
        except IntegrityError as exc:
            session.rollback()
            raise HTTPException(status_code=409, detail="Duplicate event nonce") from exc
        return {"event_id": incoming.id, "new_alert_ids": alerts}

    @app.get("/api/v1/sensors")
    def sensor_coverage(_: Operator, session: DB):
        """Enumerate configured sensors, even if they have never sent a packet."""
        now = utcnow()
        known = {row.sensor_id: row for row in session.scalars(select(SensorStatus)).all()}
        result = []
        for sensor_id in sorted(settings.sensor_keys):
            row = known.get(sensor_id)
            last_seen = row.last_seen_at if row else None
            result.append({"sensor_id": sensor_id, "asset_id": row.asset_id if row else None,
                           "expected_asset_id": settings.sensor_assets.get(sensor_id),
                           "binding_mode": "explicit" if sensor_id in settings.sensor_assets else "first_contact",
                           "status": sensor_state(last_seen, now),
                           "last_seen_at": as_utc_iso(last_seen) if last_seen else None,
                           "last_event_at": as_utc_iso(row.last_event_at) if row and row.last_event_at else None,
                           "heartbeat_count": row.heartbeat_count if row else 0,
                           "event_count": row.event_count if row else 0})
        return {"stale_after_seconds": SENSOR_STALE_SECONDS, "sensors": result,
                "summary": {"configured": len(result),
                            "healthy": sum(s["status"] == "healthy" for s in result),
                            "gaps": sum(s["status"] != "healthy" for s in result),
                            "explicitly_enrolled": len(settings.sensor_assets)},
                "assurance": "Last accepted signed contact, not host integrity or assured network coverage"}

    @app.get("/api/v1/session")
    def operator_session(operator: Operator):
        return {"operator_id": operator.operator_id, "role": operator.role,
                "capabilities": {"triage": operator.role in ("analyst", "admin"),
                                 "audit_integrity": operator.role == "admin"}}

    @app.get("/api/v1/overview")
    def overview(_: Operator, session: DB):
        events = session.scalar(select(func.count()).select_from(SecurityEvent)) or 0
        alerts = session.scalar(select(func.count()).select_from(Alert)) or 0
        severe = session.scalar(select(func.count()).select_from(Alert).where(Alert.severity == "high")) or 0
        assets = session.scalar(select(func.count(func.distinct(SecurityEvent.asset_id)))) or 0
        return {"events": events, "alerts": alerts, "high_alerts": severe, "assets": assets,
                "mode": "read-only", "defensive_enforcement": "not-installed"}

    @app.get("/api/v1/events")
    def events(_: Operator, session: DB):
        rows = session.scalars(select(SecurityEvent).order_by(SecurityEvent.received_at.desc()).limit(100)).all()
        return [{"id": e.id, "asset_id": e.asset_id, "sensor_id": e.sensor_id, "category": e.category,
                 "action": e.action, "source_ip": e.source_ip,
                 "observed_at": as_utc_iso(e.observed_at)} for e in rows]

    @app.get("/api/v1/alerts")
    def alerts(_: Operator, session: DB):
        rows = session.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(100)).all()
        return [{"id": a.id, "severity": a.severity, "title": a.title, "explanation": a.explanation,
                 "asset_id": a.asset_id, "source_ip": a.source_ip, "rule_id": a.rule_id,
                 "state": a.state, "evidence_count": a.evidence_count,
                 "created_at": as_utc_iso(a.created_at)} for a in rows]

    @app.get("/api/v1/alerts/{alert_id}/evidence")
    def evidence(alert_id: str, _: Operator, session: DB):
        alert = session.get(Alert, alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        rows = session.execute(select(SecurityEvent).join(AlertEvidence, AlertEvidence.event_id == SecurityEvent.id)
                               .where(AlertEvidence.alert_id == alert_id).order_by(SecurityEvent.observed_at)).scalars().all()
        return [{"event_id": e.id, "sensor_id": e.sensor_id, "action": e.action,
                 "asset_id": e.asset_id, "source_ip": e.source_ip,
                 "observed_at": as_utc_iso(e.observed_at)} for e in rows]

    @app.get("/api/v1/alerts/{alert_id}/history")
    def alert_history(alert_id: str, _: Operator, session: DB):
        if session.get(Alert, alert_id) is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        decisions = session.scalars(select(AlertDecision).where(
            AlertDecision.alert_id == alert_id
        ).order_by(AlertDecision.id.desc()).limit(50)).all()
        return [{"id": row.id, "previous_state": row.previous_state,
                 "new_state": row.new_state, "actor": row.actor,
                 "reason": row.reason, "decided_at": as_utc_iso(row.decided_at)} for row in decisions]

    @app.post("/api/v1/alerts/{alert_id}/transition")
    async def transition_alert(alert_id: str, request: Request, operator: Analyst, session: DB):
        # Explicit streaming limit ensures untrusted reasons cannot create unbounded bodies.
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 2048:
                raise HTTPException(status_code=413, detail="Triage body too large")
        try:
            instruction = TriageRequest.model_validate_json(raw)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail="Invalid triage instruction") from exc
        allowed = {"open": "investigating", "investigating": "resolved", "resolved": "investigating"}
        if allowed.get(instruction.expected_state) != instruction.new_state:
            raise HTTPException(status_code=422, detail="Unsupported incident state transition")
        lock_audit_head(session)  # Enforce deterministic writer ordering.
        # A state-conditional SQL UPDATE prevents stale-state overwrites.
        changed = session.execute(update(Alert).where(
            Alert.id == alert_id, Alert.state == instruction.expected_state
        ).values(state=instruction.new_state).returning(Alert.id)).scalar_one_or_none()
        if changed is None:
            session.rollback()
            if session.get(Alert, alert_id) is None:
                raise HTTPException(status_code=404, detail="Alert not found")
            raise HTTPException(status_code=409, detail="Alert state changed; refresh before retrying")
        decision = AlertDecision(alert_id=alert_id, previous_state=instruction.expected_state,
                                 new_state=instruction.new_state, reason=instruction.reason, actor=operator.operator_id)
        session.add(decision)
        session.flush()
        append_audit(session, settings.audit_key, actor=operator.operator_id, action="alert.transition",
                     resource=f"decision:{decision.id}:{decision_digest(decision)}")
        session.commit()
        return {"alert_id": alert_id, "state": instruction.new_state, "decision_id": decision.id}

    @app.get("/api/v1/audit/integrity")
    def audit_integrity(_: Admin, session: DB):
        anchored_valid, legacy_count = verify_event_evidence(session)
        return {"valid": verify_chain(session, settings.audit_key) and verify_case_decisions(session) and anchored_valid,
                "records": session.scalar(select(func.count()).select_from(AuditRecord)) or 0,
                "event_payload_assurance": ("integrity_failed" if not anchored_valid else
                                             "partial_legacy" if legacy_count else "anchored"),
                "legacy_unanchored_events": legacy_count,
                "assurance": "HMAC chain, triage and v1 event-row cross-check; legacy event payloads are unverifiable; not externally immutable"}

    return app
