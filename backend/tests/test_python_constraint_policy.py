"""Offline release-policy failures must stay observable."""
from pathlib import Path

import pytest
from scripts.verify_python_constraints import parse_constraints, check_installed

PATH = Path(__file__).resolve().parents[1] / "constraints" / "py312-linux-ci.txt"


def test_reviewed_constraints_are_complete_and_exact():
    pins = parse_constraints(PATH.read_text())
    assert len(pins) >= 30
    assert pins["psycopg"] == pins["psycopg-binary"]
    assert pins["fastapi"] and pins["alembic"]


@pytest.mark.parametrize("bad", [
    "fastapi>=0.1", "--extra-index-url https://evil.example/", 
    "fastapi==1.0\nFastAPI==2.0", "fastapi==1.0\nfastapi==2.0", 
    "git+https://github.com/example/repo", "fastapi==1.0 ; python_version>'3'",
])
def test_bad_constraints_fail_closed(bad):
    base = PATH.read_text()
    with pytest.raises(ValueError):
        parse_constraints(base + "\n" + bad + "\n")


def test_installed_mismatch_and_missing_dependencies_rejected():
    pins = parse_constraints(PATH.read_text())
    actual = {k: v for k, v in pins.items()}
    assert not check_installed(pins, actual, postgres=True)
    actual["sqlalchemy"] = "0.0.0"
    assert any("sqlalchemy" in err for err in check_installed(pins, actual, postgres=True))
    del actual["psycopg"]
    assert any("psycopg" in err for err in check_installed(pins, actual, postgres=True))
    assert not any("psycopg" in err for err in check_installed(pins, actual, postgres=False))


def test_duplicate_normalized_names_fail():
    base = PATH.read_text()
    with pytest.raises(ValueError, match="Duplicate"):
        parse_constraints(base + "\nSQLAlchemy==2.1.4\n")
