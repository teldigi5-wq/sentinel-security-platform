"""Offline, no-deletion SQLite event export and independent bundle verification.

From backend/: python -m scripts.export_event_evidence export /path/sentinel.db /private/new-bundle --days 30
               python -m scripts.export_event_evidence verify /private/new-bundle
Never pass audit secrets on the command line.
"""
import argparse
import json
import os
from pathlib import Path
from sentinel.evidence_export import export_event_evidence, verify_event_export


def main() -> int:
    parser = argparse.ArgumentParser(description="Create or verify private, sealed event export (no event deletion)")
    modes = parser.add_subparsers(dest="mode", required=True)
    export = modes.add_parser("export")
    export.add_argument("database", type=Path)
    export.add_argument("destination", type=Path)
    export.add_argument("--days", type=int, default=30)
    export.add_argument("--max-events", type=int, default=1000)
    verify = modes.add_parser("verify")
    verify.add_argument("destination", type=Path)
    args = parser.parse_args()
    key = os.getenv("SENTINEL_AUDIT_KEY", "")
    if len(key) < 32:
        parser.error("SENTINEL_AUDIT_KEY is required in the environment")
    try:
        if args.mode == "export":
            report = export_event_evidence(args.database, args.destination, key,
                                           older_than_days=args.days, max_events=args.max_events)
        else:
            report = verify_event_export(args.destination, key)
    except (ValueError, RuntimeError, OSError) as exc:
        parser.exit(1, f"Evidence operation refused: {type(exc).__name__}: {exc}\n")
    # Only non-sensitive counts, timestamps and hashes; no source IPs or raw records.
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
