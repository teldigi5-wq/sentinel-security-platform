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
