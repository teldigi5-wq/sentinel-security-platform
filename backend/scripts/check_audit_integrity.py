"""Run a least-privilege, read-only localhost integrity check.

Exit: 0 authenticated anchored events; 2 integrity/legacy/empty gap;
      1 unknown (auth, connectivity, malformed/oversized response).
This does not install continuous monitoring; schedule only if appropriate.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sentinel.coverage_probe import CoverageProbeError, read_private_token
from sentinel.integrity_probe import IntegrityProbeError, fetch_integrity


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only, localhost-only Sentinel audit integrity probe")
    parser.add_argument("--token-file", required=True, type=Path, help="Absolute private 0600 viewer credential file")
    parser.add_argument("--port", type=int, default=8000, help="Sentinel loopback API port")
    parser.add_argument("--json", action="store_true", help="Print only non-sensitive evidence state")
    args = parser.parse_args(argv)
    try:
        token = read_private_token(args.token_file)
        result = fetch_integrity(port=args.port, token=token)
    except (CoverageProbeError, IntegrityProbeError):
        print("SENTINEL AUDIT UNKNOWN", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result.summary(), sort_keys=True))
    else:
        print("SENTINEL AUDIT " + ("CLEAR" if result.clear else "GAP") + ": " + result.state)
    return 0 if result.clear else 2


if __name__ == "__main__":
    raise SystemExit(main())
