"""Local-only operational probe. Exit 0 healthy, 2 coverage gap, 1 unknown.

From backend/: python -m scripts.check_sensor_coverage --token-file /private/viewer.token
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sentinel.coverage_probe import CoverageProbeError, fetch_coverage, read_private_token


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only, localhost-only Sentinel sensor coverage monitor")
    parser.add_argument("--token-file", required=True, type=Path, help="Absolute path to a private viewer-scoped token file")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--json", action="store_true", help="Aggregate counts only, never host identities")
    args = parser.parse_args(argv)
    try:
        token = read_private_token(args.token_file)
        result = fetch_coverage(port=args.port, token=token)
    except CoverageProbeError as exc:
        print(f"SENTINEL COVERAGE UNKNOWN: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result.summary(), sort_keys=True))
    else:
        level = "OK" if result.clear else "GAP"
        print(f"SENTINEL COVERAGE {level}: {result.healthy}/{result.configured} recent contacts; "
              f"{result.stale} stale; {result.never_seen} never seen")
    return 0 if result.clear else 2


if __name__ == "__main__":
    raise SystemExit(main())
