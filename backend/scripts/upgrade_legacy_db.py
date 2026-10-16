"""Run only with Sentinel stopped and after making an offline recovery plan."""
import argparse
import getpass
from pathlib import Path
from sentinel.legacy_upgrade import upgrade_legacy_sqlite


def main():
    parser = argparse.ArgumentParser(description="Guarded one-time migration from a v0.4 SQLite DB")
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--backup", type=Path, required=True, help="New, non-existing backup file")
    parser.add_argument("--confirm-offline", action="store_true", required=True)
    args = parser.parse_args()
    key = getpass.getpass("Current Sentinel audit HMAC key (hidden): ")
    upgrade_legacy_sqlite(args.database, args.backup, key)
    print("Legacy database migrated. Retain the offline backup securely.")


if __name__ == "__main__":
    main()
