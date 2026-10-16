"""Read-only current-state Linux qualification observations. Not host certification."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from sentinel.coverage_probe import CoverageProbeError, read_private_token
from sentinel.host_observation import HostObservationError, observe


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Read-only Sentinel Linux runtime observation")
    parser.add_argument("--sensor-id", required=True, help="Explicitly enrolled sensor ID")
    parser.add_argument("--token-file", type=Path, required=True, help="Absolute private viewer token path")
    parser.add_argument("--port", type=int, default=8000, help="Sentinel localhost API port")
    parser.add_argument("--json-out", type=Path, help="Create-only private JSON evidence path")
    args = parser.parse_args(argv)
    try:
        token = read_private_token(args.token_file)
        report = observe(sensor_id=args.sensor_id, token=token, port=args.port)
    except (HostObservationError, CoverageProbeError):
        # No exception text: unexpected backend errors may contain sensitive details.
        print("SENTINEL HOST OBSERVATION UNKNOWN", file=sys.stderr)
        return 1
    output = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json_out is not None:
        if not args.json_out.is_absolute():
            parser.error("Report path must be absolute")
        fd = None
        try:
            fd = os.open(args.json_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                fd = None
                stream.write(output)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError:
            if fd is not None:
                os.close(fd)
            parser.error("Cannot create private non-overwriting evidence file")
    print(output, end="")
    return 0 if report["all_checks_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
