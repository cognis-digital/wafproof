"""Tests for SARIF 2.1.0 export."""

import json
from pathlib import Path

from wafproof.cli import main
from wafproof.corpus import builtin_corpus
from wafproof.detector import load_ruleset, ruleset_detector
from wafproof.metrics import evaluate
from wafproof.sarif import SARIF_VERSION, evaluation_to_sarif

EXAMPLE_RULES = Path(__file__).resolve().parent.parent / "examples" / "rules.json"


def _eval_with(rules_obj, corpus=None):
    import tempfile

    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False, encoding="utf-8"
    ) as fh:
        json.dump(rules_obj, fh)
        path = fh.name
    detect = ruleset_detector(load_ruleset(path))
    return evaluate(detect, corpus or builtin_corpus())


def test_clean_run_has_no_results():
    detect = ruleset_detector(load_ruleset(EXAMPLE_RULES))
    ev = evaluate(detect, builtin_corpus())
    doc = evaluation_to_sarif(ev)
    assert doc["version"] == SARIF_VERSION
    assert doc["runs"][0]["results"] == []


def test_envelope_shape_is_valid_sarif():
    doc = evaluation_to_sarif(_eval_with({"rules": [{"id": "x", "pattern": "zzz"}]}))
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "wafproof"
    assert driver["organization"] == "Cognis Digital"
    # every rule referenced by a result must exist in driver.rules
    rule_ids = {r["id"] for r in driver["rules"]}
    for res in doc["runs"][0]["results"]:
        assert res["ruleId"] in rule_ids
        assert res["level"] in ("error", "warning")
        assert res["message"]["text"]
        assert res["partialFingerprints"]


def test_fn_becomes_coverage_gap_error():
    # a ruleset that matches nothing -> every malicious entry is a FN
    ev = _eval_with({"rules": [{"id": "x", "pattern": "match-nothing-zzz"}]})
    doc = evaluation_to_sarif(ev)
    fn_results = [
        r for r in doc["runs"][0]["results"] if r["ruleId"] == "wafproof/coverage-gap"
    ]
    assert fn_results
    assert all(r["level"] == "error" for r in fn_results)
    n_malicious = sum(1 for e in builtin_corpus() if e["label"] == "malicious")
    assert len(fn_results) == n_malicious


def test_fp_becomes_false_alarm_warning():
    # an over-broad rule flags benign prose -> false positives appear
    ev = _eval_with({"rules": [{"id": "x", "pattern": "."}]})
    doc = evaluation_to_sarif(ev)
    fp_results = [
        r for r in doc["runs"][0]["results"] if r["ruleId"] == "wafproof/false-alarm"
    ]
    assert fp_results
    assert all(r["level"] == "warning" for r in fp_results)


def test_metrics_carried_in_run_properties():
    ev = _eval_with({"rules": [{"id": "x", "pattern": "zzz"}]})
    doc = evaluation_to_sarif(ev)
    props = doc["runs"][0]["properties"]
    assert "metrics" in props
    assert "recall" in props["metrics"]
    assert "perCategory" in props


def test_fingerprints_are_stable_across_runs():
    ev1 = _eval_with({"rules": [{"id": "x", "pattern": "zzz"}]})
    ev2 = _eval_with({"rules": [{"id": "x", "pattern": "zzz"}]})
    fp1 = {
        r["partialFingerprints"]["wafproofCanaryId/v1"]
        for r in evaluation_to_sarif(ev1)["runs"][0]["results"]
    }
    fp2 = {
        r["partialFingerprints"]["wafproofCanaryId/v1"]
        for r in evaluation_to_sarif(ev2)["runs"][0]["results"]
    }
    assert fp1 == fp2


def test_cli_run_sarif_to_stdout(capsys):
    rc = main(["run", "--rules", str(EXAMPLE_RULES), "--sarif", "-"])
    assert rc == 0
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    # clean ruleset -> no findings, and the table must NOT also print
    assert "Detection evaluation" not in out


def test_cli_run_sarif_to_file_also_prints_table(tmp_path, capsys):
    dest = tmp_path / "out.sarif.json"
    rc = main(["run", "--rules", str(EXAMPLE_RULES), "--sarif", str(dest)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Detection evaluation" in out
    assert dest.exists()
    doc = json.loads(dest.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"


def test_cli_report_sarif_records_findings(tmp_path):
    weak = tmp_path / "weak.json"
    weak.write_text(
        json.dumps({"rules": [{"id": "x", "pattern": "match-nothing-zzz"}]}),
        encoding="utf-8",
    )
    dest = tmp_path / "report.sarif.json"
    rc = main(["report", "--rules", str(weak), "--fail-under", "0.8", "--sarif", str(dest)])
    assert rc == 1  # gate fails (low recall) but SARIF is still written
    doc = json.loads(dest.read_text(encoding="utf-8"))
    assert len(doc["runs"][0]["results"]) > 0
