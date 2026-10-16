"""Operator-driven, non-destructive Linux host recovery evidence capture."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from sentinel.coverage_probe import CoverageProbeError, read_private_token
from sentinel.host_acceptance import HostAcceptanceError, PHASES, capture, verify


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Read-only Sentinel recovery checkpoint witness")
    parser.add_argument("--evidence-dir", type=Path, required=True,
                        help="New private absolute directory for baseline; existing for later phases")
    parser.add_argument("--verify", action="store_true", help="Offline final sequence check, no token required")
    parser.add_argument("--phase", choices=PHASES, help="Operator-attested stage to capture")
    parser.add_argument("--sensor-id", help="Explicitly enrolled Linux sensor identifier")
    parser.add_argument("--token-file", type=Path, help="Owner-only private viewer token file")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    if args.verify:
        if args.phase or args.sensor_id or args.token_file:
            parser.error("Offline verification may not be combined with capture parameters")
        try:
            result = verify(args.evidence_dir)
        except (HostAcceptanceError, OSError, ValueError):
            print("SENTINEL HOST QUALIFICATION UNKNOWN", file=sys.stderr)
            return 1
        print(json.dumps(result, sort_keys=True))
        return 0
    if not args.phase or not args.sensor_id or args.token_file is None:
        parser.error("Capture requires --phase, --sensor-id and --token-file")
    try:
        token = read_private_token(args.token_file)
        report = capture(phase=args.phase, directory=args.evidence_dir,
                         sensor_id=args.sensor_id, port=args.port, token=token)
    except (HostAcceptanceError, CoverageProbeError, OSError, ValueError):
        print("SENTINEL HOST QUALIFICATION UNKNOWN", file=sys.stderr)
        return 1
    # Never print identities, token, log paths, raw events, service lifetime markers or directory contents.
    print(json.dumps({"schema": report["schema"], "phase": report["phase"],
                      "status": report["status"], "host_certified": False}, sort_keys=True))
    return 0 if report["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
