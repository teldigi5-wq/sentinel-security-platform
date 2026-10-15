"""Deterministic detection rules. These raise alerts; they NEVER perform retaliation."""
import uuid
from datetime import timedelta
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .models import SecurityEvent, Alert, AlertEvidence


def evaluate(session: Session, event: SecurityEvent) -> list[str]:
    findings = []
    if event.action == "malware_detected":
        findings.append(("malware-indicator-v1", "high", "Malware indicator observed",
                         "A configured endpoint sensor reported a malware indicator. Validate its underlying detection before containment.",
                         f"malware:{event.id}"))
    elif event.action == "privilege_escalation_denied":
        findings.append(("privilege-denial-v1", "medium", "Privilege escalation attempt denied",
                         "A managed endpoint reported a denied elevation attempt. Review surrounding events.",
                         f"privilege:{event.id}"))
    elif event.action == "auth_failure" and event.source_ip:
        window_start = event.observed_at - timedelta(minutes=5)
        recent = session.scalars(select(SecurityEvent).where(
            SecurityEvent.action == "auth_failure",
            SecurityEvent.source_ip == event.source_ip,
            SecurityEvent.asset_id == event.asset_id,
            SecurityEvent.observed_at >= window_start,
            SecurityEvent.observed_at <= event.observed_at,
        ).order_by(SecurityEvent.observed_at.desc()).limit(5)).all()
        if len(recent) >= 5:
            # A bucket makes deduplication stable across the same 5-minute slot.
            bucket = int(event.observed_at.timestamp() // 300)
            findings.append(("auth-failure-burst-v1", "medium", "Repeated authentication failures",
                             "Five or more authentication failures were observed from the same source against one asset in five minutes.",
                             f"auth:{event.asset_id}:{event.source_ip}:{bucket}"))
    elif event.action == "network_denied" and event.source_ip:
        # A burst of denied connections from one source against a single asset is
        # an investigation signal, not proof of hostile identity or intent.
        window_start = event.observed_at - timedelta(minutes=2)
        recent = session.scalars(select(SecurityEvent).where(
            SecurityEvent.action == "network_denied",
            SecurityEvent.source_ip == event.source_ip,
            SecurityEvent.asset_id == event.asset_id,
            SecurityEvent.observed_at >= window_start,
            SecurityEvent.observed_at <= event.observed_at,
        ).order_by(SecurityEvent.observed_at.desc()).limit(12)).all()
        if len(recent) >= 12:
            bucket = int(event.observed_at.timestamp() // 120)
            findings.append(("network-denial-burst-v1", "medium", "Burst of denied network connections",
                             "Twelve or more network-denied events were reported from the same source against one asset in two minutes. Investigate before blocking.",
                             f"network:{event.asset_id}:{event.source_ip}:{bucket}"))
    created = []
    for rule_id, severity, title, explanation, fingerprint in findings:
        existing = session.scalar(select(Alert).where(Alert.fingerprint == fingerprint))
        if existing:
            # Avoid duplicate alert rows while linking this evidence.
            seen = session.scalar(select(AlertEvidence.id).where(
                AlertEvidence.alert_id == existing.id, AlertEvidence.event_id == event.id
            ))
            if seen is None:
                session.add(AlertEvidence(alert_id=existing.id, event_id=event.id))
                existing.evidence_count += 1
            continue
        alert = Alert(id=str(uuid.uuid4()), rule_id=rule_id, fingerprint=fingerprint,
                      severity=severity, title=title, explanation=explanation,
                      asset_id=event.asset_id, source_ip=event.source_ip, evidence_count=1)
        session.add(alert)
        session.flush()
        # For auth bursts, link the evidence records involved in the threshold.
        evidence = recent if rule_id in ("auth-failure-burst-v1", "network-denial-burst-v1") else [event]
        for e in evidence:
            session.add(AlertEvidence(alert_id=alert.id, event_id=e.id))
        alert.evidence_count = len(evidence)
        created.append(alert.id)
    return created
