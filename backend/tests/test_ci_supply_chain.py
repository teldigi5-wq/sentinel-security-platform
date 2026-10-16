"""Offline checks for CI dependency provenance and least-privilege defaults.

These tests deliberately do not claim that an ephemeral npm lock is a reviewed,
reproducible lockfile or that SHA-pinning proves upstream integrity.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
FRONTEND_LOCK = ROOT / "frontend" / "package-lock.json"


def _workflow():
    return WORKFLOW.read_text(encoding="utf-8")


def test_actions_are_pinned_to_full_commit_ids():
    text = _workflow()
    actions = re.findall(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", text, re.MULTILINE)
    assert len(actions) >= 10, "CI must retain all existing verification jobs"
    for ref in actions:
        assert re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}", ref), ref
    assert any(ref.startswith("actions/checkout@") for ref in actions)
    assert any(ref.startswith("actions/setup-node@") for ref in actions)
    assert any(ref.startswith("actions/setup-python@") for ref in actions)
    assert any(ref.startswith("actions/upload-artifact@") for ref in actions)


def test_ci_declares_read_only_default_token():
    text = _workflow()
    assert re.search(r"(?m)^permissions:\n\s+contents:\s+read\s*$", text)
    assert not re.search(r"(?m)^\s+(?:contents|actions|pull-requests):\s+write\s*$", text)


def test_frontend_ci_uses_committed_lock_without_mutating_it():
    text = _workflow()
    frontend = text.split("\n  frontend:\n", 1)[1].split("\n  postgres:\n", 1)[0]
    assert FRONTEND_LOCK.is_file(), "A reviewed lockfile must be committed"
    assert "node scripts/verify-lockfile.mjs" in frontend
    assert "npm ci --no-audit --no-fund" in frontend
    assert "npm ls --depth=0" in frontend
    assert "npm install" not in frontend
    assert "sentinel-frontend-candidate-lock" not in frontend
    assert frontend.index("verify-lockfile.mjs") < frontend.index("npm ci") < frontend.index("npm ls")
    assert (ROOT / "docs" / "DEPENDENCY_RELEASE_EVIDENCE.md").is_file()


def test_production_required_jobs_fail_on_dependency_audit_findings():
    """Required backend/frontend status checks must include actual online audits.

    The GitHub ruleset already makes these two jobs required. Do not move the
    scans to an optional informational job or allow scanner failures to pass.
    """
    text = _workflow()
    backend = text.split("\n  backend:\n", 1)[1].split("\n  linux-recovery-drill:\n", 1)[0]
    frontend = text.split("\n  frontend:\n", 1)[1].split("\n  postgres:\n", 1)[0]
    assert "pip-audit==2.10.1" in backend
    assert "python -m pip_audit" in backend
    assert "--no-deps --disable-pip --strict" in backend
    assert "backend/constraints/py312-linux-ci.txt" in backend
    assert "--format json" in backend
    assert "npm audit --json --audit-level=high" in frontend
    assert "sentinel-frontend-vulnerabilities.json" in frontend
    for section in (backend, frontend):
        assert "continue-on-error: true" not in section
        assert "|| true" not in section
        assert "exit 0" not in section
    assert "if: always()" in backend
    assert "if: always()" in frontend
    assert "sentinel-python-vulnerabilities.json" in backend
    assert "sentinel-python-vulnerability-audit" in backend
    assert "sentinel-frontend-vulnerability-audit" in frontend
    assert (ROOT / "docs" / "DEPENDENCY_VULNERABILITY_AUDIT.md").is_file()
