"""Local operator maintenance: backup, verify and new-file recovery for SQLite."""
import argparse
import os
from pathlib import Path
from sentinel.backup import create_backup, verify_backup, restore_backup


def main() -> None:
    parser = argparse.ArgumentParser(description='Sentinel SQLite backup and recovery')
    commands = parser.add_subparsers(dest='action', required=True)
    for verb in ('backup', 'verify', 'restore'):
        sub = commands.add_parser(verb)
        sub.add_argument('source', type=Path, help='SQLite path for backup; backup directory for verify/restore')
        if verb != 'verify':
            sub.add_argument('destination', type=Path, help='New private backup directory or new restore database file')
    args = parser.parse_args()
    audit_key = os.getenv('SENTINEL_AUDIT_KEY', '')
    if len(audit_key) < 32:
        parser.error('SENTINEL_AUDIT_KEY (strong, at least 32 characters) required')
    if args.action == 'backup':
        metadata = create_backup(args.source, args.destination, audit_key)
    elif args.action == 'verify':
        metadata = verify_backup(args.source, audit_key)
    else:
        metadata = restore_backup(args.source, args.destination, audit_key)
    print(f"{args.action} validated: {metadata['schema_revision']}; audit entries={metadata['audit_entries']}")


if __name__ == '__main__':
    main()