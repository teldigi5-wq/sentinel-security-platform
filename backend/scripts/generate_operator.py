"""Create one new high-entropy operator bearer token and its SHA-256 enrollment digest.

Run locally and store the token in a password manager. Only put the digest in
SENTINEL_OPERATORS, which is still a sensitive access-control configuration.
"""
import hashlib
import secrets

if __name__ == "__main__":
    token = secrets.token_urlsafe(48)
    print("Operator token (keep private; not recoverable from digest):", token)
    print("token_sha256:", hashlib.sha256(token.encode()).hexdigest())
    print("Enroll with one role: viewer, analyst, or admin")
