"""Keep the npm security fix pinned and reviewable while Next.js carries old PostCSS."""
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[2]


def test_postcss_high_severity_advisory_is_remediated_in_reviewed_lock():
    package = json.loads((ROOT / "frontend/package.json").read_text())
    lock = json.loads((ROOT / "frontend/package-lock.json").read_text())
    actual = lock["packages"]["node_modules/postcss"]
    assert package["overrides"]["postcss"] == "8.5.23"
    assert actual["version"] == "8.5.23"
    assert actual["resolved"] == "https://registry.npmjs.org/postcss/-/postcss-8.5.23.tgz"
    assert actual["integrity"] == (
        "sha512-g50586zr4bZmwFiTlflMu8E0bDTb5I5gertgwAKmsdUlTQIhZtunzUlD1WSzwcVWPoAVpsrA6vlfCD7oXvRwgg=="
    )
    assert actual["dependencies"] == {
        "nanoid": "^3.3.16", "picocolors": "^1.1.1", "source-map-js": "^1.2.1"
    }
