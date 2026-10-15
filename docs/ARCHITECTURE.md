# Sentinel v0.1 — architectural decision record

## Mission and guarantees

A local-first security operations foundation. Evidence is collected by named sensors using signed, replay-resistant messages. Deterministic detection produces traceable, inspectable alerts. The operator dashboard is read-only and requires a separate credential. **There is no offensive module, autonomous remediation, firewall management or active network prevention in this version.**

## Deployed logical components

```text
[Lab event emitter / future authorized endpoint adapter]
               |
    HMAC-SHA256, time + nonce, bounded JSON
               v
      [FastAPI ingestion gateway] ----> [Replay nonce registry]
               |                                  |
        strict Pydantic schema                    v
               v                       [SQLite / PostgreSQL]
       [Security event table] --------------------|
               |                                  |
       deterministic rules -----------------------|
               v                                  |
      [Alert + evidence links] -------------------|
               |                                  |
     [HMAC-linked audit log] ---------------------|
               |
      [Bearer-protected REST API]
               |
    [Next.js operator command center]
```

This design has no guaranteed whole-network visibility. Traffic telemetry requires authorized sensors at relevant network points; endpoint coverage requires agents; prevention requires separate enforcement controls and explicit policy decisions.

## ADR-001: modular monolith before microservices

Small, typed modules and explicit boundaries make security reasoning, integration testing and reliable local installation simpler. Split workers into dedicated processes only when operational measurements justify it.

## ADR-002: SQLite for development, PostgreSQL for future multi-user work

SQLite minimizes mandatory services. SQLAlchemy supports a PostgreSQL driver, but migrations, concurrency controls, backups and HA are **not complete**. Initial work is single-operator/single-process. Starting multiple ingestion workers risks duplicate detectors and competing audit writers.

## ADR-003: deterministic alerts

AI does not determine authorization, trust boundaries or security enforcement. Signatures protect sensor-to-core authenticity and integrity, not the truthfulness of the originating sensor. The v0.1 rule engine detects:

- `auth-failure-burst-v1`: at least five failures in five minutes, grouped by source IP + targeted asset.
- `network-denial-burst-v1`: at least twelve denied connections in two minutes, grouped by source IP + targeted asset.
- `malware-indicator-v1`: a sensor-reported malware indicator (requires independent validation).
- `privilege-denial-v1`: a sensor-reported denied elevation attempt.

There is currently no behavior-modeling claim and **no attacker attribution**. Source IPs are observations, not identities. There are no built-in endpoint agents yet.

## ADR-004: private operator interface

The Next.js UI requests an operator credential interactively, keeping it only in volatile React state. The backend validates its bearer token using constant-time comparison and deliberately disables interactive API documentation. No server secret may be included in `NEXT_PUBLIC_*`. This is a single-operator MVP credential, not enterprise IAM, SSO, MFA, key rotation or RBAC.

## ADR-005: trusted audits with limitations

Audit entries are HMAC-chained. The integrity check catches edits to a retained chain provided the key remains trustworthy. This alone does **not** prevent deletion, total replacement, rollback, truncation, server compromise or malicious write access. Multiwriter safety, immutable external anchors, independent storage, retention and rotation must be implemented before making forensic non-repudiation claims.

## Planned phases, NOT IMPLEMENTED

1. Migration-managed PostgreSQL and robust concurrent ingestion queue.
2. Enrollment and key rotation, mTLS and OIDC with MFA.
3. Agent adapters (Wazuh, Suricata, Zeek) with validated data contracts.
4. Threat-intelligence enrichment and evidence-based relationship graph.
5. Read-only AI incident copilot with deterministic tools, adversarial evaluation and no implicit authority.
6. Approval-gated firewall/endpoint enforcement with rollback and operator supervision.
7. Isolated, explicitly authorized attack-defense laboratory; no hack-back, retaliation or malware redistribution.

## Hardware economics

The core runs locally without mandatory hosted services or model APIs. Continuous availability requires an always-on host, electricity, networking, storage, sensor installation, operations and monitoring. Large monitoring systems and local language models are optional components with substantial resource demands.
