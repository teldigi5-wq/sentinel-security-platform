# Operator identity and access — v0.4

Sentinel remains **localhost-only, pre-production**, and has **no MFA, SSO, token expiry,
per-operator login history, session revocation, brute-force rate limiting, or public access design**.
A bearer token grants its role until removed from the operator mapping. Operators must not
share credentials. Tokens are high-entropy random secrets, **not human passwords**.

## Enrollment

1. Run `python backend/scripts/generate_operator.py` independently for each operator.
2. Save each raw token in a trusted password manager; do not commit, screenshot or log it.
3. Add a JSON mapping to the private service environment under `SENTINEL_OPERATORS`:

```json
{
  "auditor": {"role": "viewer", "token_sha256": "REPLACE_WITH_ACTUAL_64_LOWERCASE_HEX_DIGEST"},
  "soc.analyst": {"role": "analyst", "token_sha256": "REPLACE_WITH_ANOTHER_64_LOWERCASE_HEX_DIGEST"},
  "admin.001": {"role": "admin", "token_sha256": "REPLACE_WITH_THIRD_64_LOWERCASE_HEX_DIGEST"}
}
```

The example uses deliberately invalid digest placeholders. Provide the mapping as a **single JSON environment value**, never a checked-in configuration. Up to 32 operator identities are supported.

When `SENTINEL_OPERATORS` exists, the legacy `SENTINEL_OPERATOR_TOKEN` is ignored, even when it matches.
An empty or invalid map aborts startup (fail closed). Remove or unset the legacy token
once new operators can authenticate. Confirm `GET /api/v1/session` shows the intended identity.

## Roles and enforcement

| Endpoint/action | Viewer | Analyst | Admin |
| --- | --- | --- | --- |
| Overview, alerts, events, evidence, history | Read | Read | Read |
| Change incident triage state and reason | Denied (403) | Allowed | Allowed |
| Verify local audit integrity | Denied (403) | Denied (403) | Allowed |

All authorization decisions are in the API; hiding UI controls is only an additional usability measure.
Incident decision records and linked audit entries name the specific enrolled operator ID.

## Rotation, removal and response

To revoke a bearer token, remove its enrollment from the private mapping and restart the API.
For rotation, generate a new token, replace the digest, restart the API, and distribute the new
secret through a trusted channel. Restart requirements and lack of short-lived tokens are
known risks. Changing the role is an administrator-managed configuration change.

The SHA-256 digest is used only to index a **random 48-byte bearer token**, not to store
password hashes. Human-selected passwords must not be enrolled through this mechanism.
The private operator mapping, audit key, sensor keys and all secrets must be kept off GitHub.

**Before any remote or production access:** add short-lived sessions or OIDC/MFA,
rate limits, stronger operator audit and secret rotation, authenticated TLS, and penetration-test verification.
