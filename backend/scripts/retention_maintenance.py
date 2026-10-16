"""Offline, SQLite-only nonce retention: preview by default, explicit apply + backup.

Example (from backend directory):
  python -m scripts.retention_maintenance /private/sentinel.db --days 7
  python -m scripts.retention_maintenance /private/sentinel.db --days 7 --apply --backup-dir /private/new-backup
"""
import argparse
import json
import os
from pathlib import Path

from sentinel.retention import nonce_retention


def main():
    parser = argparse.ArgumentParser(description='Preview safe replay-nonce retention; never delete event evidence')
    parser.add_argument('database', type=Path, help='Existing local SQLite file')
    parser.add_argument('--days', type=int, default=7, help='Retain at least 24 hours, default 7 days')
    parser.add_argument('--apply', action='store_true', help='Require a newly created verified backup')
    parser.add_argument('--backup-dir', type=Path, help='New private backup directory (mandatory with --apply)')
    args = parser.parse_args()
    audit_key = os.getenv('SENTINEL_AUDIT_KEY', '')
    if len(audit_key) < 32:
        parser.error('SENTINEL_AUDIT_KEY is required; secrets must not appear in CLI arguments')
    try:
        report = nonce_retention(args.database, audit_key, days=args.days,
                                 apply=args.apply, backup_dir=args.backup_dir)
    except (ValueError, RuntimeError, OSError) as exc:
        parser.exit(1, f'Retention not applied: {type(exc).__name__}: {exc}\n')
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
