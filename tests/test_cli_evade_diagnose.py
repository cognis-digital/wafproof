"""End-to-end CLI tests for the 'evade' and 'diagnose' subcommands."""

import json
from pathlib import Path

import pytest

from wafproof.cli import main

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_RULES = ROOT / "examples" / "rules.json"
OVERBROAD = ROOT / "demos" / "01-tighten-overbroad-rule" / "overbroad-rules.json"


# ===========================================================================
# evade
# ===========================================================================
def test_evade_text_output(capsys):
    rc = main(["evade", "--rules", str(EXAMPLE_RULES)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Evasion-resistance evaluation" in out
    assert "By transform" in out
    assert "url-encode" in out


def test_evade_json_output(capsys):
    rc = main(["evade", "--rules", str(EXAMPLE_RULES), "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert 0.0 <= out["score"] <= 1.0
    assert "per_transform" in out
    assert "canaries" in out
    assert out["mutations_caught"] <= out["mutations_total"]


def test_evade_only_filter(capsys):
    rc = main(["evade", "--rules", str(EXAMPLE_RULES), "--only", "case-toggle", "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert set(out["per_transform"]) <= {"case-toggle"}


def test_evade_unknown_transform_errors():
    with pytest.raises(SystemExit):
        main(["evade", "--rules", str(EXAMPLE_RULES), "--only", "nope"])


def test_evade_gate_fail(capsys):
    # example ruleset is ~49% robust -> a 0.9 threshold must fail
    rc = main(["evade", "--rules", str(EXAMPLE_RULES), "--fail-under", "0.9"])
    assert rc == 1
    assert "GATE [FAIL]" in capsys.readouterr().out


def test_evade_gate_pass(capsys):
    rc = main(["evade", "--rules", str(EXAMPLE_RULES), "--fail-under", "0.1"])
    assert rc == 0
    assert "GATE [PASS]" in capsys.readouterr().out


def test_evade_gate_json(capsys):
    rc = main(["evade", "--rules", str(EXAMPLE_RULES), "--fail-under", "0.9", "--json"])
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["gate"]["metric"] == "evasion_resistance"
    assert out["gate"]["passed"] is False


def test_evade_with_callable(tmp_path, capsys):
    det = tmp_path / "det.py"
    det.write_text("def d(s):\n    return '<' in s or 'OR' in s\n", encoding="utf-8")
    rc = main(["evade", "--callable", f"{det}:d", "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert "score" in out


def test_evade_requires_one_detector():
    with pytest.raises(SystemExit):
        main(["evade"])


def test_evade_fail_under_out_of_range():
    with pytest.raises(SystemExit):
        main(["evade", "--rules", str(EXAMPLE_RULES), "--fail-under", "2.0"])


# ===========================================================================
# diagnose
# ===========================================================================
def test_diagnose_text_output(capsys):
    rc = main(["diagnose", "--rules", str(EXAMPLE_RULES)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Ruleset diagnostics" in out
    assert "Per rule" in out


def test_diagnose_json_output(capsys):
    rc = main(["diagnose", "--rules", str(EXAMPLE_RULES), "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["rule_count"] >= 10
    assert out["dead_rule_count"] == 0
    assert out["overbroad_rule_count"] == 0


def test_diagnose_overbroad_demo(capsys):
    rc = main(["diagnose", "--rules", str(OVERBROAD), "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["overbroad_rule_count"] >= 1
    assert "sqli-apostrophe" in out["overbroad_rules"]


def test_diagnose_fail_on_overbroad(capsys):
    rc = main(["diagnose", "--rules", str(OVERBROAD), "--fail-on-overbroad"])
    assert rc == 1
    assert "Overbroad rules" in capsys.readouterr().out


def test_diagnose_fail_on_overbroad_clean_passes():
    rc = main(["diagnose", "--rules", str(EXAMPLE_RULES), "--fail-on-overbroad"])
    assert rc == 0


def test_diagnose_fail_on_dead_with_empty_corpus(tmp_path):
    # an empty custom corpus makes every rule dead
    empty = tmp_path / "empty.json"
    empty.write_text("[]", encoding="utf-8")
    rc = main([
        "diagnose", "--rules", str(EXAMPLE_RULES),
        "--corpus", str(empty), "--fail-on-dead",
    ])
    assert rc == 1


def test_diagnose_requires_rules():
    with pytest.raises(SystemExit):
        main(["diagnose"])


def test_diagnose_callable_rejected(tmp_path):
    # diagnose has no --callable; passing it is an unrecognized arg
    with pytest.raises(SystemExit):
        main(["diagnose", "--callable", "x:y"])


def test_diagnose_bad_ruleset_errors(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["diagnose", "--rules", str(bad)])
