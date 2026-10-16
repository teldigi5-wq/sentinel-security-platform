"""Offline contract verifying the published frontend dependency lock.

The Node validator is also exercised by frontend CI on the real lockfile.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_frontend_lock_matches_manifest_and_has_verified_sources():
    manifest = json.loads((ROOT / "frontend/package.json").read_text())
    lock = json.loads((ROOT / "frontend/package-lock.json").read_text())
    assert lock["lockfileVersion"] == 3
    assert lock["name"] == manifest["name"]
    assert lock["version"] == manifest["version"]
    assert len(lock["packages"]) >= 10
    for field in ("dependencies", "devDependencies"):
        assert lock["packages"][""][field] == manifest[field]
    for name in set(manifest["dependencies"]) | set(manifest["devDependencies"]):
        assert "node_modules/" + name in lock["packages"]
    for name, pkg in lock["packages"].items():
        if not name:
            continue
        assert pkg["resolved"].startswith("https://registry.npmjs.org/"), name
        assert re.fullmatch(r"sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}", pkg["integrity"]), name
        assert pkg["version"]


def test_frontend_lock_validator_is_committed():
    source = (ROOT / "frontend/scripts/verify-lockfile.mjs").read_text()
    assert "registry.npmjs.org" in source
    assert "process.exitCode = 1" in source
    assert "Unapproved package source" in source


def test_node_validator_rejects_tampered_lock_when_node_is_available(tmp_path):
    import shutil
    import subprocess
    import sys

    if shutil.which("node") is None:
        import pytest
        pytest.skip("Node.js is not installed on this backend test runner")

    package_file = ROOT / "frontend/package.json"
    original = json.loads((ROOT / "frontend/package-lock.json").read_text())
    validator = ROOT / "frontend/scripts/verify-lockfile.mjs"
    target = tmp_path / "package-lock.json"

    tampered = json.loads(json.dumps(original))
    target_pkg = next(k for k in tampered["packages"] if k)
    tampered["packages"][target_pkg]["resolved"] = "http://untrusted.invalid/evil.tgz"
    target.write_text(json.dumps(tampered))
    result = subprocess.run(["node", str(validator), str(package_file), str(target)],
                            check=False, capture_output=True, text=True)
    assert result.returncode == 1
    assert "Unapproved package source" in result.stderr

    tampered = json.loads(json.dumps(original))
    tampered["packages"][target_pkg].pop("integrity", None)
    target.write_text(json.dumps(tampered))
    result = subprocess.run(["node", str(validator), str(package_file), str(target)],
                            check=False, capture_output=True, text=True)
    assert result.returncode == 1
    assert "Missing or invalid integrity" in result.stderr

    tampered = json.loads(json.dumps(original))
    tampered["packages"][""]["dependencies"]["next"] = "^0.0.1"
    target.write_text(json.dumps(tampered))
    result = subprocess.run(["node", str(validator), str(package_file), str(target)],
                            check=False, capture_output=True, text=True)
    assert result.returncode == 1
    assert "differs from package.json" in result.stderr
