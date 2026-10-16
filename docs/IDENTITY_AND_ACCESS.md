# Operator identity and access — v0.7

Sentinel remains **localhost-only, pre-production**. Legacy/static mode has no automatic expiry or immediate revocation. Optional database mode adds expiry and revocation but neither mode provides MFA, SSO, brute-force rate limiting, or a public access design.
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


## Database-backed credentials (opt-in v0.7)

1. Stop the API, take a verified backup, and from `backend/` run `python -m alembic -c alembic.ini upgrade head` with the existing private database URL. Do not discard the audit key.
2. Provide `SENTINEL_DATABASE_URL` and `SENTINEL_AUDIT_KEY` to the trusted local administrator shell. From `backend/`, run:

```bash
python scripts/operator_credentials.py enroll security-admin admin --valid-days 30 --token-file /PRIVATE/OUTSIDE-REPO/admin.secret
```

3. Transfer the new `0600` file's one-time bearer token to a trusted secret manager. Do **not** commit it, screenshot it, or transmit it through logs.
4. Set `SENTINEL_AUTH_MODE=database` and **unset both** `SENTINEL_OPERATOR_TOKEN` and `SENTINEL_OPERATORS` entirely; leaving even empty values causes startup rejection. Restart the locally bound API.
5. Inspect only non-secret metadata using `python scripts/operator_credentials.py list`.

Rotate an active credential without changing its role:

```bash
python scripts/operator_credentials.py rotate security-admin OLD_ID --valid-days 30 --token-file /PRIVATE/OUTSIDE-REPO/new.secret
```

Immediately revoke a selected credential using `python scripts/operator_credentials.py revoke CREDENTIAL_ID`. Existing sessions using that credential fail at the next request. The last active administrator is protected from accidental revocation. Expiry is checked per request and capped at 90 days. Credentials are not recoverable from hashed database records; a trusted local administrator must issue a replacement.

**Limits:** This is not phishing-resistant MFA or public IAM. Anyone able to modify the database or steal bearer credentials remains a serious risk. Use TLS, MFA/SSO, request throttling, managed recovery and independent security review before exposing any interface remotely.
