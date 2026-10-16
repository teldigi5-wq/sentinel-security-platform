"""Local-only operator token enrollment, rotation, revocation and listing."""
import argparse
import json
import os
from pathlib import Path
from sentinel.credential_lifecycle import create_or_rotate, list_credentials, revoke_credential

def main():
    parser = argparse.ArgumentParser(description="Sentinel offline operator credentials (no HTTP administration)")
    subs = parser.add_subparsers(dest="command", required=True)
    enroll = subs.add_parser("enroll")
    enroll.add_argument("operator_id")
    enroll.add_argument("role", choices=["viewer", "analyst", "admin"])
    enroll.add_argument("--valid-days", type=int, default=30)
    enroll.add_argument("--token-file", type=Path, required=True)
    rotate = subs.add_parser("rotate")
    rotate.add_argument("operator_id")
    rotate.add_argument("credential_id", type=int)
    rotate.add_argument("--valid-days", type=int, default=30)
    rotate.add_argument("--token-file", type=Path, required=True)
    revoke = subs.add_parser("revoke")
    revoke.add_argument("credential_id", type=int)
    subs.add_parser("list")
    args = parser.parse_args()
    url = os.getenv("SENTINEL_DATABASE_URL", "sqlite:///./sentinel.db")
    audit_key = os.getenv("SENTINEL_AUDIT_KEY", "")
    if args.command == "enroll":
        cred_id = create_or_rotate(url, audit_key, operator_id=args.operator_id, role=args.role,
                                   valid_days=args.valid_days, secret_file=args.token_file)
        print(f"Enrolled credential #{cred_id}; token written once to private file")
    elif args.command == "rotate":
        cred_id = create_or_rotate(url, audit_key, operator_id=args.operator_id, role=None,
                                   previous_id=args.credential_id, valid_days=args.valid_days,
                                   secret_file=args.token_file)
        print(f"Rotated credential #{cred_id}; old token revoked")
    elif args.command == "revoke":
        revoke_credential(url, audit_key, args.credential_id)
        print("Credential revoked")
    else:
        print(json.dumps(list_credentials(url, audit_key), indent=2))

if __name__ == "__main__":
    main()
