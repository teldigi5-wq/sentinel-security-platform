"""Run offline, unprivileged Sentinel Linux collector qualification.

Example: python -m scripts.drill_linux_collector --json-out /tmp/sentinel-drill.json
Never installs services, probes hosts, or accesses /var/log/auth.log.
"""
import argparse
import json
import os
from pathlib import Path
from sentinel.deployment_drill import execute


def write_private_report(path: Path, report: dict) -> None:
    if not path.is_absolute() or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("Absolute report path and no-follow support required")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if fd >= 0:
            os.close(fd)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Isolated collector recovery qualification (no real host)")
    parser.add_argument("--json-out", type=Path, help="New absolute report path; never overwrite")
    args = parser.parse_args(argv)
    report = execute()
    if args.json_out:
        try:
            write_private_report(args.json_out, report)
        except (OSError, ValueError):
            parser.error("Could not safely create new report file")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["all_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
