"""Offline Sentinel Linux collector deployment preflight; no privileged actions."""
import argparse
import json
import os
from pathlib import Path
from sentinel.deployment_preflight import inspect_deployment


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="SENTINEL read-only Linux service preflight")
    parser.add_argument("--source", type=Path, default=Path("/var/log/auth.log"))
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/sentinel-sensor"))
    parser.add_argument("--key-file", type=Path, default=Path("/etc/sentinel/collector.key"))
    parser.add_argument("--config-file", type=Path, default=Path("/etc/sentinel/collector.conf"))
    parser.add_argument("--unit-file", type=Path, default=Path("/etc/systemd/system/sentinel-ssh-collector.service"))
    parser.add_argument("--fixture", action="store_true", help="CI/test fixture only; skips real service-account qualification")
    parser.add_argument("--json-out", type=Path, help="Exclusive private report file; never overwrites")
    args = parser.parse_args(argv)
    report = inspect_deployment(source=args.source, state_dir=args.state_dir, key_file=args.key_file,
                                config_file=args.config_file, unit_file=args.unit_file, fixture=args.fixture)
    output = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json_out is not None:
        # Never follow a symlink or replace existing evidence. Fail safely on error.
        if not args.json_out.is_absolute():
            parser.error("Report destination must be an absolute path")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(args.json_out, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(output)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError:
            parser.error("Cannot safely create a new report file")
    print(output, end="")
    return 0 if report["all_checks_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
