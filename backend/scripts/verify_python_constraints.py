"""Offline policy validation for reviewed Sentinel Python 3.12 CI constraints.

Does not contact a package index. Tests installed versions after pip resolves
the separately declared project dependencies using these constraints.
"""
import argparse
import importlib.metadata as metadata
import re
from pathlib import Path

_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*$")
_VERSION = re.compile(r"^[0-9][A-Za-z0-9.+!_-]*$")
_REQUIRED = frozenset({"fastapi", "uvicorn", "pydantic", "sqlalchemy", "alembic", "pytest", "httpx"})
_POSTGRES = frozenset({"psycopg", "psycopg-binary"})


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_constraints(text: str) -> dict[str, str]:
    versions = {}
    for index, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.count("==") != 1:
            raise ValueError(f"Invalid constraint at line {index}: expected exact == pin")
        name, version = (x.strip() for x in line.split("==", 1))
        if not _NAME.fullmatch(name) or not _VERSION.fullmatch(version):
            raise ValueError(f"Unsafe constraint at line {index}")
        key = normalize(name)
        if key in versions:
            raise ValueError(f"Duplicate constraint for {key} at line {index}")
        versions[key] = version
    missing = (_REQUIRED | _POSTGRES) - versions.keys()
    if missing:
        raise ValueError("Missing required pinned dependencies: " + ", ".join(sorted(missing)))
    if versions["psycopg"] != versions["psycopg-binary"]:
        raise ValueError("psycopg and psycopg-binary must have matching versions")
    return versions


def check_installed(pins: dict[str, str], installed: dict[str, str], *, postgres: bool = False) -> list[str]:
    seen = {normalize(k): v for k, v in installed.items()}
    errors = []
    required = _REQUIRED | (_POSTGRES if postgres else set())
    for name in sorted(required):
        if name not in seen:
            errors.append(f"Required distribution not installed: {name}")
    for name, pinned in sorted(pins.items()):
        if name in seen and seen[name] != pinned:
            errors.append(f"Installed version violates constraint: {name}")
    return errors


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Verify installed Python versions against reviewed CI constraints")
    parser.add_argument("--file", type=Path, default=Path(__file__).resolve().parents[1] / "constraints" / "py312-linux-ci.txt")
    parser.add_argument("--postgres", action="store_true")
    args = parser.parse_args(argv)
    try:
        pins = parse_constraints(args.file.read_text(encoding="utf-8"))
        actual = {normalize(d.metadata["Name"]): d.version for d in metadata.distributions() if d.metadata.get("Name")}
        errors = check_installed(pins, actual, postgres=args.postgres)
    except (OSError, ValueError) as exc:
        print("Constraint policy failed:", exc)
        return 1
    if errors:
        for error in errors:
            print("Constraint policy failed:", error)
        return 1
    print(f"Verified {sum(n in actual for n in pins)} pinned installed distributions; PostgreSQL check: {args.postgres}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
