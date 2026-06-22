"""Verify every shipped demo actually produces the outcome its SCENARIO.md
documents. These tests are the guard that keeps the demos honest."""

import json
from pathlib import Path

import pytest

from wafproof.cli import main
from wafproof.corpus import builtin_corpus, validate_corpus
from wafproof.detector import load_callable, load_ruleset, ruleset_detector
from wafproof.metrics import evaluate

DEMOS = Path(__file__).resolve().parent.parent / "demos"


def _eval(rules_path: Path, corpus_path: Path | None = None):
    detect = ruleset_detector(load_ruleset(rules_path))
    if corpus_path:
        raw = json.loads(corpus_path.read_text(encoding="utf-8"))
        corpus = validate_corpus(raw["entries"] if isinstance(raw, dict) else raw)
    else:
        corpus = builtin_corpus()
    return evaluate(detect, corpus)


def test_all_demo_dirs_have_scenario():
    dirs = [d for d in DEMOS.iterdir() if d.is_dir()]
    assert len(dirs) >= 8
    for d in dirs:
        assert (d / "SCENARIO.md").exists(), f"{d.name} missing SCENARIO.md"


def test_all_demo_json_is_valid():
    for jf in DEMOS.rglob("*.json"):
        json.loads(jf.read_text(encoding="utf-8"))  # raises on malformed


def test_demo01_overbroad_rule_has_two_false_alarms():
    ev = _eval(DEMOS / "01-tighten-overbroad-rule" / "overbroad-rules.json")
    fp_ids = {e.id for e in ev.false_positives}
    assert fp_ids == {"sqli-benign-name", "sqli-benign-prose"}
    assert ev.overall.recall == 1.0


def test_demo02_refactor_gate_fails():
    rules = DEMOS / "02-coverage-gap-after-refactor" / "simplified-rules.json"
    rc = main(["report", "--rules", str(rules), "--fail-under", "0.9"])
    assert rc == 1
    ev = _eval(rules)
    fn_ids = {e.id for e in ev.false_negatives}
    assert fn_ids == {"sqli-union-select", "sqli-comment-bypass", "sqli-stacked-drop"}


def test_demo03_custom_corpus_surfaces_one_fp():
    d = DEMOS / "03-custom-app-traffic-corpus"
    ev = _eval(
        Path(__file__).resolve().parent.parent / "examples" / "rules.json",
        d / "app-traffic-corpus.json",
    )
    assert ev.overall.recall == 1.0
    assert {e.id for e in ev.false_positives} == {"review-text-drop"}


def test_demo04_callable_loads_and_catches_all():
    spec = str(DEMOS / "04-callable-allowlist-detector" / "detector.py") + ":is_malicious"
    detect = load_callable(spec)
    ev = evaluate(detect, builtin_corpus())
    assert ev.overall.recall == 1.0  # allowlist catches every attack shape
    assert ev.false_positives  # and the scoping trade-off shows up as FPs


def test_demo05_candidate_yields_one_fn_and_one_fp():
    ev = _eval(DEMOS / "05-ci-gate-and-sarif" / "candidate-rules.json")
    assert {e.id for e in ev.false_negatives} == {"pt-windows-backslash"}
    assert {e.id for e in ev.false_positives} == {"xss-benign-article"}


def test_demo06_api_rules_score_perfectly():
    d = DEMOS / "06-graphql-nosql-corpus"
    ev = _eval(d / "api-rules.json", d / "api-corpus.json")
    assert ev.overall.recall == 1.0
    assert ev.overall.false_positive_rate == 0.0
    assert set(ev.per_category) == {"nosql", "graphql"}


def test_demo07_lookup_rules_catch_nested_evasion():
    d = DEMOS / "07-jndi-lookup-canary"
    ev = _eval(d / "lookup-rules.json", d / "lookup-corpus.json")
    assert ev.overall.recall == 1.0
    assert ev.overall.false_positive_rate == 0.0
    flagged = {e.id: e.flagged for e in ev.entries}
    assert flagged["lookup-nested-env"] is True  # the evasion is caught
    assert flagged["lookup-benign-shell-var"] is False  # ${HOME} left alone


def test_demo09_normalizing_detector_lifts_evasion_resistance():
    """The normalizing wrapper must keep perfect recall AND pass the 0.9
    evasion-resistance gate, while the raw ruleset fails it -- the whole point
    of demo 09."""
    from wafproof.analyze import robustness

    spec = str(
        DEMOS / "09-evasion-resistance" / "normalizing_detector.py"
    ) + ":detect"
    detect = load_callable(spec)
    # recall and FPR unchanged
    ev = evaluate(detect, builtin_corpus())
    assert ev.overall.recall == 1.0
    assert ev.overall.false_positive_rate == 0.0
    # robustness lifted above the gate
    rep = robustness(detect, builtin_corpus())
    assert rep.score >= 0.9
    # while the raw literal ruleset is well below it
    raw = ruleset_detector(
        load_ruleset(Path(__file__).resolve().parent.parent / "examples" / "rules.json")
    )
    assert robustness(raw, builtin_corpus()).score < 0.6


def test_demo09_gate_exit_codes():
    spec = str(DEMOS / "09-evasion-resistance" / "normalizing_detector.py") + ":detect"
    assert main(["evade", "--callable", spec, "--fail-under", "0.9"]) == 0
    raw = str(Path(__file__).resolve().parent.parent / "examples" / "rules.json")
    assert main(["evade", "--rules", raw, "--fail-under", "0.9"]) == 1


def test_demo08_sarif_diff_detects_regression():
    import importlib.util

    d = DEMOS / "08-regression-sarif-baseline"
    spec = importlib.util.spec_from_file_location("sarif_diff", d / "sarif_diff.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    rc = mod.main([str(d / "v1-baseline.sarif"), str(d / "v2-regressed.sarif")])
    assert rc == 1  # candidate introduces new findings
    rc_same = mod.main([str(d / "v1-baseline.sarif"), str(d / "v1-baseline.sarif")])
    assert rc_same == 0
