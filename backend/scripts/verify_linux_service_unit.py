"""Offline real-systemd-parser unit check; not a Linux-host certificate."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from sentinel.systemd_unit_verify import UNIT_RELATIVE, UnitSyntaxError, UnitToolUnavailable, verify_unit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline systemd collector unit verification")
    parser.add_argument("--json", action="store_true", help="Print safe, bounded verification metadata")
    args = parser.parse_args(argv)
    path = Path(__file__).resolve().parents[2] / UNIT_RELATIVE
    try:
        outcome = verify_unit(path)
    except UnitSyntaxError:
        print("SENTINEL SYSTEMD UNIT INVALID", file=sys.stderr)
        return 2
    except UnitToolUnavailable:
        print("SENTINEL SYSTEMD UNIT VERIFICATION UNKNOWN", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(outcome, sort_keys=True))
    else:
        print("SENTINEL SYSTEMD UNIT SYNTAX VERIFIED (NO HOST CERTIFICATION)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
