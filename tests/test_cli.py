"""End-to-end tests for the CLI: run, corpus, report, gate exit codes, and the
shipped example ruleset against the built-in corpus."""

import json
from pathlib import Path

import pytest

from wafproof.cli import main
from wafproof.corpus import builtin_corpus
from wafproof.detector import load_ruleset, ruleset_detector
from wafproof.metrics import evaluate

EXAMPLE_RULES = Path(__file__).resolve().parent.parent / "examples" / "rules.json"


def test_example_ruleset_loads():
    rules = load_ruleset(EXAMPLE_RULES)
    assert len(rules) >= 10


def test_example_ruleset_catches_every_canary_without_false_alarms():
    """The shipped example ruleset is curated to score perfectly on the built-in
    corpus: it should flag every malicious canary and no benign look-alike."""
    detect = ruleset_detector(load_ruleset(EXAMPLE_RULES))
    ev = evaluate(detect, builtin_corpus())
    missed = [(e.category, e.id, e.text) for e in ev.false_negatives]
    false_alarms = [(e.category, e.id, e.text) for e in ev.false_positives]
    assert missed == [], f"example ruleset missed canaries: {missed}"
    assert false_alarms == [], f"example ruleset false-flagged: {false_alarms}"
    assert ev.overall.recall == 1.0
    assert ev.overall.false_positive_rate == 0.0


def test_run_command_json(capsys):
    rc = main(["run", "--rules", str(EXAMPLE_RULES), "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["overall"]["recall"] == 1.0
    assert "per_category" in out


def test_run_command_table(capsys):
    rc = main(["run", "--rules", str(EXAMPLE_RULES)])
    assert rc == 0
    text = capsys.readouterr().out
    assert "detection rate" in text
    assert "Per category" in text


def test_corpus_command_lists(capsys):
    rc = main(["corpus"])
    assert rc == 0
    text = capsys.readouterr().out
    assert "corpus entries" in text
    assert "[xss]" in text


def test_corpus_command_category_filter(capsys):
    rc = main(["corpus", "--category", "sqli", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data
    assert all(e["category"] == "sqli" for e in data)


def test_corpus_command_bad_category_errors():
    with pytest.raises(SystemExit):
        main(["corpus", "--category", "nope"])


def test_report_passes_with_good_ruleset(capsys):
    rc = main(["report", "--rules", str(EXAMPLE_RULES), "--fail-under", "0.9"])
    assert rc == 0
    assert "GATE [PASS]" in capsys.readouterr().out


def test_report_fails_when_recall_below_threshold(tmp_path, capsys):
    # A ruleset that catches almost nothing -> low recall -> gate fails.
    weak = tmp_path / "weak.json"
    weak.write_text(
        json.dumps({"rules": [{"id": "x", "pattern": "this-matches-nothing-xyzzy"}]}),
        encoding="utf-8",
    )
    rc = main(["report", "--rules", str(weak), "--fail-under", "0.8"])
    assert rc == 1
    assert "GATE [FAIL]" in capsys.readouterr().out


def test_report_json_includes_gate(tmp_path, capsys):
    rc = main(["report", "--rules", str(EXAMPLE_RULES), "--fail-under", "0.5", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["gate"]["passed"] is True
    assert data["gate"]["metric"] == "recall"


def test_requires_exactly_one_detector():
    with pytest.raises(SystemExit, match="exactly one"):
        main(["run"])


def test_callable_detector_end_to_end(tmp_path, capsys):
    mod = tmp_path / "always.py"
    # A detector that flags everything: recall 1.0 but high false-positive rate.
    mod.write_text("def detect(s):\n    return True\n", encoding="utf-8")
    rc = main(["run", "--callable", f"{mod}:detect", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["overall"]["recall"] == 1.0
    assert data["overall"]["false_positive_rate"] == 1.0


def test_custom_corpus(tmp_path, capsys):
    custom = tmp_path / "c.json"
    custom.write_text(
        json.dumps(
            {
                "entries": [
                    {"id": "m", "category": "t", "label": "malicious", "text": "ZAP"},
                    {"id": "b", "category": "t", "label": "benign", "text": "ok"},
                ]
            }
        ),
        encoding="utf-8",
    )
    rules = tmp_path / "r.json"
    rules.write_text(
        json.dumps({"rules": [{"id": "r", "pattern": "ZAP"}]}), encoding="utf-8"
    )
    rc = main(
        ["run", "--rules", str(rules), "--corpus", str(custom), "--json"]
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["overall"]["tp"] == 1
    assert data["overall"]["tn"] == 1


def test_fail_under_out_of_range():
    with pytest.raises(SystemExit, match="between 0 and 1"):
        main(["report", "--rules", str(EXAMPLE_RULES), "--fail-under", "2"])
