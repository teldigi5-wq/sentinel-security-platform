# Sentinel v0.7 — architectural decision record

## Mission and guarantees

A local-first security operations foundation. Evidence is collected by named sensors using signed, replay-resistant messages. Deterministic detection produces traceable, inspectable alerts. The operator dashboard requires a separate credential and now supports logged case-state decisions; it cannot execute containment or firewall actions. **There is no offensive module, autonomous remediation, firewall management or active network prevention in this version.**

## Deployed logical components

```text
[Lab emitter / opt-in read-only Linux SSH log collector]
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
      [Operator case decisions] ------------------|
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

SQLite minimizes mandatory services. SQLAlchemy supports a PostgreSQL driver, but migrations, concurrency controls, backups and HA are **not complete**. Initial work is single-process with optional individually enrolled operator roles. Starting multiple ingestion workers risks duplicate detectors and competing audit writers.

## ADR-003: deterministic alerts

AI does not determine authorization, trust boundaries or security enforcement. Signatures protect sensor-to-core authenticity and integrity, not the truthfulness of the originating sensor. The v0.2 rule engine continues to detect:

- `auth-failure-burst-v1`: at least five failures in five minutes, grouped by source IP + targeted asset.
- `network-denial-burst-v1`: at least twelve denied connections in two minutes, grouped by source IP + targeted asset.
- `malware-indicator-v1`: a sensor-reported malware indicator (requires independent validation).
- `privilege-denial-v1`: a sensor-reported denied elevation attempt.

There is currently no behavior-modeling claim and **no attacker attribution**. Source IPs are observations, not identities. There are no built-in endpoint agents yet.

## ADR-004: private operator interface

The Next.js UI requests an operator credential interactively, keeping it only in volatile React state. The backend validates its bearer token using constant-time comparison and deliberately disables interactive API documentation. No server secret may be included in `NEXT_PUBLIC_*`. v0.4 optionally authenticates individually enrolled role-bearing tokens, but this is still not enterprise IAM, SSO, MFA, key rotation or remote-user security.

## ADR-005: trusted audits with limitations

Audit entries are HMAC-chained. Case decisions are committed alongside audit references containing SHA-256 digests of the decision contents. Integrity verification checks decision histories and current alert state against these references, plus the signed audit chain. The integrity check catches edits to a retained chain provided the key remains trustworthy. This alone does **not** prevent deletion, total replacement, rollback, truncation, server compromise or malicious write access. Multiwriter safety, immutable external anchors, independent storage, retention and rotation must be implemented before making forensic non-repudiation claims.

## ADR-006: operator triage is not automated response

Only explicitly authenticated operators can change an alert from open to investigating, from investigating to resolved, or from resolved back to investigating. Changes require a rationale and are persisted with a decision history entry and audit binding. A conditional SQL update guards against most stale-state updates and returns HTTP 409 on conflict. Configured per-operator credentials attribute decisions to individual operator IDs; the deprecated shared credential cannot. SSO/MFA, short-lived tokens, versioned concurrency and stronger audit anchoring remain future work. No network, endpoint or identity enforcement is exposed by this API.


## ADR-007: Least-privilege Linux SSH log sensor

An explicit file-based Linux SSH collector provides the first non-synthetic telemetry source. It reads only an operator-selected local regular file, refuses symlinks and unsafe permissions, extracts source IPs from a strictly limited SSHD failure format, and emits bounded HMAC-authenticated events **only to literal loopback**. Raw log lines, usernames and ports are never sent. First enrollment defaults to tailing the current file rather than backfilling historical records; controlled `--backfill` is explicit. It persists a private, atomic cursor with a per-log-generation random identifier; position-derived nonces allow a failed checkpoint to retry without a duplicate stored event. It refuses malformed state, incomplete or oversized records, insecure cursor permissions and failed transmissions instead of silently dropping them. No daemon/service installation or privileged defensive response is introduced.

**Threat/accuracy limits:** syslog records can be spoofed by an actor who controls the source; a source IP is not attacker attribution. Authentication log access still requires host permissions. Parser coverage is narrow and distro-dependent. Timestamp is the UTC **collection time**, not necessarily the original SSH event time; backfilling historical logs can generate false bursts. Raw-file ingestion offers no guarantee of complete visibility under rapid log rotation or truncation; a true systemd journal reader with trustworthy cursor metadata and tested operating permissions is future work. The state directory must be on a trusted filesystem and should be writable by only one collector process. Local API HMAC authenticates the sensor, not the provenance of each originating log line.

## Planned phases, NOT IMPLEMENTED

1. Migration-managed PostgreSQL and robust concurrent ingestion queue.
2. Enrollment and key rotation, mTLS and OIDC with MFA.
3. General endpoint/network adapters (Wazuh, Suricata, Zeek), agent enrollment and event-source provenance with validated contracts.
4. Threat-intelligence enrichment and evidence-based relationship graph.
5. Read-only AI incident copilot with deterministic tools, adversarial evaluation and no implicit authority.
6. Approval-gated firewall/endpoint enforcement with rollback and operator supervision.
7. Isolated, explicitly authorized attack-defense laboratory; no hack-back, retaliation or malware redistribution.

## Hardware economics

The core runs locally without mandatory hosted services or model APIs. Continuous availability requires an always-on host, electricity, networking, storage, sensor installation, operations and monitoring. Large monitoring systems and local language models are optional components with substantial resource demands.

## ADR-008: v0.4 individually enrolled bearer identities and RBAC

A private `SENTINEL_OPERATORS` mapping enrolls individual random bearer tokens by SHA-256
fingerprint and explicit `viewer`/`analyst`/`admin` role. When present, the mapping
disables shared-token authentication entirely. The backend enforces each endpoint's
role; frontend navigation reflects server-reported capabilities but is not a policy
boundary. Case decisions are attributed to the enrolled operator ID and bound to
the local HMAC audit chain. The legacy shared token is still supported **only** for
controlled local backward compatibility with the old environment configuration.

This is a transitional, manually managed local model without MFA, SSO, expiring
sessions, dedicated authentication datastore, or remote-user protections. No claim
of enterprise IAM qualification is made.

## ADR-009: migration-controlled schema, deterministic concurrent audits (v0.5)

The API now **refuses to start** unless the Alembic revision matches the current head (`0003_operator_credentials` in v0.7). No `Base.metadata.create_all` is invoked at runtime. New SQLite and PostgreSQL databases are initialized by an explicit Alembic `upgrade head`; a guarded legacy SQLite migration requires an audit-validated schema, current HMAC key, and a private backup. A failed migration must be investigated and restored from backup; migrations are not guaranteed online or reversible.

All ingestion and case state changes acquire an audit head lock **before** writing dependent records. PostgreSQL uses a row-level `FOR UPDATE` lock; SQLite acquires a database write lock through a no-op update. Each event, decision and audit tail update is part of the same transaction; rollback undoes all of them. The local audit integrity checker verifies hash chaining plus audit head count and tail to detect certain deletions/forks. This is not an immutable/off-host log, and a compromised DB plus key can still forge history. Long-held locks limit throughput: this design prioritizes correctness for a small local SOC over high ingestion rates. Benchmark and introduce a durable queue before enterprise-scale deployment.

The PostgreSQL integration test runs only when a dedicated test database URL is supplied. Deployment must explicitly enable PostgreSQL support and validate backup/restore, operational privileges, rollback and resource pressure.


## ADR-010: Offline disaster recovery and authenticated snapshots (v0.6)

Local SQLite backup uses Python's online SQLite backup API rather than copying
the main database file (which would miss committed WAL data). Validation occurs
against the *snapshot* and includes `PRAGMA integrity_check`, the migration
revision, the HMAC-linked audit head and triage state cross-check. A bounded
manifest records the snapshot checksum and audit head, with HMAC authentication
under the existing audit key. Recovery authenticates and re-verifies its inputs,
copies to a private temporary file, and publishes only to a nonexistent target
using a no-replace hard link. Directory entries are synced on POSIX where supported.

The recovery workflow does not authorize remote actions or expose an API. Its
assumptions are a trusted local host, private destination directories, operator-
controlled audit key and an offline restore target. Backups are not encrypted,
not independently immutable, not automatically scheduled, and not tested for
crash consistency under a forcibly terminated filesystem. Key rotation needs a
documented retention/rekey policy for old backups. PostgreSQL backup is outside
this module's scope.


## ADR-011: Local credential expiration, revocation and role-preserving rotation (v0.7)

Static environment-defined credentials remain the default for backward compatibility.
A deliberately opt-in `SENTINEL_AUTH_MODE=database` moves operator identities
into migration-controlled `operator_credentials` records. The credential is
a cryptographically random bearer secret; only its SHA-256 fingerprint is stored.
Operators retain `viewer`, `analyst` or `admin` permissions enforced at the API.
Revocation and expiration are checked against the database on **every HTTP
request**, without an in-memory credential cache. There is no automatic fallback
to the legacy token in database mode. Startup requires an active administrator;
local OS-controlled enrollment can create replacements if that credential expires.

A CLI, not an Internet-reachable API, enrolls, revokes and rotates credentials.
The CLI uses the existing serialized audit-head lock and transactional audit
records. Successful rotation revokes the old credential and writes the new
fingerprint in one DB transaction. Newly generated raw secrets are written only
to exclusive, mode-0600 files; output paths must be kept outside the Git tree
and handled through a trusted secret manager. Revoking the last active admin is
forbidden unless a replacement is first enrolled or rotated.

**Unresolved limitations:** database administrators remain a powerful trust
boundary; an attacker who can modify database records may bypass ordinary role
checks. The in-database audit chain does not supply independent immutability,
MFA, distributed sessions or public-access hardening. OIDC with phishing-resistant
MFA, TLS, ratelimits, production-grade recovery and independent auditing remain
mandatory before remote deployment.

Existing v0.6 HMAC-authenticated backup snapshots can still be verified and
restored to new files by the v0.7 tool, but an explicit Alembic migration is
required after restoration and before API startup.

## v0.9: Sensor visibility without claiming protection

The collector sends signed minimal heartbeats over loopback. The server validates the same sensor HMAC/nonce envelope used by event ingestion, stores server-observed last contact in the versioned `sensor_status` table, and appends audit entries. Operator-only `GET /api/v1/sensors` lists configured sensors with `never_seen`, `healthy` or `stale` statuses; no sensor secrets are returned. The status signals API reachability, not reliable detection, no guarantee of complete log capture, and no enforcement.
