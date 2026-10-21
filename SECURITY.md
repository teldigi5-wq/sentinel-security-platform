# Responsible security development

This is an **experimental pre-production security platform**. Do not expose its operator API or UI to the public internet or rely on it as your sole network defense. Do not forward real sensitive production telemetry until data retention, role-based authorization, proper TLS/mTLS, backups and incident handling are implemented.

## Report vulnerabilities

Use private GitHub vulnerability reporting when enabled on the repository. Never post credentials or sensitive exploit details in a public issue. Maintainers should triage privately and publish tested fixes and security advisories after remediation.

## Development invariants

- No embedded secrets, public API keys or production event datasets.
- No exploit/retaliation automation, malware redistribution, or arbitrary execution through model output.
- No silent write access to protected production systems.
- No assertion of independent forensic immutability from a local HMAC chain.
- Every action that changes network policy will require explicit approved target scope, expiry and rollback in a future controlled release.

## Signed-sensor ingestion availability (v0.1)

- HMAC-verified sensor events are subject to an **in-process** allowance of 300 requests per 60 seconds per sensor identity. Requests over this allowance return HTTP 429 with Retry-After.
- Requests with invalid signatures do not consume a real sensor's allowance. The bounded in-memory state is not a shared Redis/database quota and is not persistent through restarts.
- Production multi-worker, distributed and high-volume operation requires upstream edge limits, durable per-sensor quotas, retention/TTL for security events and nonces, alerting and capacity testing. This guard alone is not a DoS guarantee.
- On a busy legitimate sensor, tune the policy via reviewed source changes and load testing before deployment; do not silently disable signature verification or audit logging.
