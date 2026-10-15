# Sentinel v0.1 — baseline threat model

## Assets

Sensor keys; operator token; audit HMAC key; event evidence; sensitive host labels/IPs; alert integrity; filesystem database; host availability; source code and CI supply chain.

## Trust boundaries

1. **Untrusted external sensor input → ingestion process.** Authenticate and validate before persistence. Signature authenticates holder of a key, not device health or event truth.
2. **Browser → operator API.** A stolen operator token permits full read access to security records. HTTPS, SSO/MFA and token rotation are required before remote production exposure.
3. **App → database.** DB compromise defeats availability/confidentiality. HMAC audit verification does not defend against a compromised key or complete rollback.
4. **Detection rules → no enforcement.** Alerts do not grant the core authority to alter firewall rules or execute commands.
5. **CI and dependency artifacts → running system.** Pin reviewed versions and add SBOM, provenance and reproducible lockfiles before mature releases.

## Current mitigations

- HMAC-SHA256 event authentication over exact raw bytes and canonical sensor ID, timestamp, nonce and payload hash.
- Time window and unique per-sensor nonce to reject replay.
- Streaming request-size cap (8 KiB), restricted event schema and IP validation.
- No arbitrary process/file/script commands in the event schema.
- Generic validation failures to avoid leaking internal server details.
- Read APIs require an operator credential. Separate sensor keys cannot read alerts.
- SQLAlchemy parameterized access; no user-controlled SQL fragments.
- Explicit CORS origin restrictions and no-store security response headers.
- Nonce + event + alert + audit update share a single database transaction.
- Tests demonstrate rejection of forged signatures, replay, malformed input, oversized input and audit edits.

## Known gaps requiring closure before production

- Operator uses a single shared bearer credential: **no per-person accountability, RBAC or MFA**.
- No per-IP/sensor rate limiting, quotas, trust enrollment, key rotation or revocation endpoints.
- No TLS termination, mutual TLS, WAF or dedicated network isolation configured by the codebase.
- No migrations, backups, restoration drills or data retention management.
- No guarantee that a compromised sensor is truthful; no sensor attestation.
- No concurrent multi-worker protections for chained audit writes or alert de-duplication races.
- Limited rules, no validated endpoint agent integration, no network packet inspection.
- Some alert time-bucket boundaries may result in extra correlated alerts; test and refine before broad deployment.
- No high-availability, SLO validation, offline-safe response controller, production monitoring or independent external audit anchor.
- Potential sensitive information in IP addresses and asset identifiers; define privacy policies and retention before non-lab use.
- Next.js local operator UI is not intended for public deployment. Its local-mode CSP currently permits Next.js inline bootstrapping; adopt per-response nonces and a stricter audited CSP before public exposure.
- Frontend dependency lockfile/build verification awaits registry access; a reproducible npm lockfile must be committed before release.

## Safety boundary

SENTINEL must not autonomously attack external addresses, return malware, hack back, collect unrelated personal information, or send unsolicited warning traffic. Warning pages, blocking, and deception may only be deployed on systems controlled by the defender with explicit approval and rollback. Public website demos must use synthetic events and never embed real access tokens or security evidence.
