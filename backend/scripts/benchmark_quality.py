"""Run synthetic detection quality gate with a nonzero exit for unexpected alerts.

Usage: from backend/, python -m scripts.benchmark_quality --json report.json
"""
import argparse
import json
from pathlib import Path
from sentinel.quality import execute


def main():
    parser = argparse.ArgumentParser(description="Synthetic-only Sentinel detection regression")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    result = execute()
    report = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.json:
        args.json.write_text(report, encoding="utf-8")
    print(report)
    return 0 if result["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
