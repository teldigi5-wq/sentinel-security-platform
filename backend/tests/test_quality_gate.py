"""Quality gate tests use real ingestion with independent SQLite databases."""
from sentinel.quality import CASES, execute


def test_rule_quality_fixture_gate():
    report = execute()
    assert report["all_passed"], report["results"]
    assert report["scenarios"] >= 15
    assert report["event_samples"] >= 90
    assert report["rule_label_counts"]["fp"] == 0
    assert report["rule_label_counts"]["fn"] == 0
    assert report["negative_scenario_alert_rate"] == 0
    assert "Synthetic" in report["scope"]


def test_quality_gate_detects_false_positive():
    positive = next(c for c in CASES if c[0] == "authentication-burst")
    unexpected = (*positive[:-1], ())
    report = execute([unexpected])
    assert not report["all_passed"]
    assert report["rule_label_counts"]["fp"] == 1


def test_quality_gate_detects_false_negative():
    negative = next(c for c in CASES if c[0] == "authentication-under-threshold")
    missing = (*negative[:-1], ("auth-failure-burst-v1",))
    report = execute([missing])
    assert not report["all_passed"]
    assert report["rule_label_counts"]["fn"] == 1
