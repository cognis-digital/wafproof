"""Tests for the robustness and ruleset-diagnostics analyses."""

from pathlib import Path

import pytest

from wafproof.analyze import (
    diagnose_from_rules,
    diagnose_ruleset,
    robustness,
)
from wafproof.corpus import builtin_corpus
from wafproof.detector import load_ruleset, ruleset_detector
from wafproof.mutate import TRANSFORM_IDS

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_RULES = ROOT / "examples" / "rules.json"
OVERBROAD = ROOT / "demos" / "01-tighten-overbroad-rule" / "overbroad-rules.json"


def _example_detector():
    return ruleset_detector(load_ruleset(EXAMPLE_RULES))


# ===========================================================================
# robustness
# ===========================================================================
def test_robustness_score_between_zero_and_one():
    rep = robustness(_example_detector(), builtin_corpus())
    assert 0.0 <= rep.score <= 1.0


def test_robustness_counts_consistent():
    rep = robustness(_example_detector(), builtin_corpus())
    assert rep.mutations_caught <= rep.mutations_total
    assert rep.mutations_total == sum(c.mutations_total for c in rep.canaries)
    assert rep.mutations_caught == sum(c.mutations_caught for c in rep.canaries)


def test_robustness_only_considers_caught_malicious():
    # the example ruleset catches all canaries at baseline -> none uncaught
    rep = robustness(_example_detector(), builtin_corpus())
    assert rep.uncaught_baseline == []
    # one CanaryRobustness per malicious entry
    mal = [e for e in builtin_corpus() if e["label"] == "malicious"]
    assert len(rep.canaries) == len(mal)


def test_robustness_uncaught_baseline_listed():
    # a detector that never fires has nothing to measure; every malicious
    # canary lands in uncaught_baseline and the score is the empty default 1.0
    rep = robustness(lambda s: False, builtin_corpus())
    assert rep.canaries == []
    assert rep.mutations_total == 0
    assert rep.score == 1.0
    mal_ids = {e["id"] for e in builtin_corpus() if e["label"] == "malicious"}
    assert set(rep.uncaught_baseline) == mal_ids


def test_robustness_perfect_detector_scores_one():
    # a detector that flags everything catches every mutation too
    rep = robustness(lambda s: True, builtin_corpus())
    assert rep.score == 1.0
    assert rep.mutations_caught == rep.mutations_total
    assert rep.mutations_total > 0


def test_robustness_example_ruleset_is_brittle_to_url_encoding():
    # the headline finding: literal-shape rules miss URL-encoded payloads
    rep = robustness(_example_detector(), builtin_corpus())
    pt = rep.per_transform
    assert "url-encode" in pt
    assert pt["url-encode"]["caught"] == 0  # blind to full url-encoding


def test_robustness_case_toggle_caught_due_to_i_flag():
    # example rules use the 'i' flag, so case-toggle should be fully caught
    rep = robustness(_example_detector(), builtin_corpus())
    ct = rep.per_transform.get("case-toggle")
    assert ct is not None
    assert ct["caught"] == ct["total"]


def test_robustness_per_category_keys():
    rep = robustness(_example_detector(), builtin_corpus())
    assert set(rep.per_category) <= {
        "xss", "sqli", "path-traversal", "command-injection"
    }
    for d in rep.per_category.values():
        assert d["caught"] <= d["total"]


def test_robustness_only_filter_restricts_transforms():
    rep = robustness(_example_detector(), builtin_corpus(), only=["case-toggle"])
    assert set(rep.per_transform) <= {"case-toggle"}


def test_robustness_only_unknown_raises():
    with pytest.raises(ValueError):
        robustness(_example_detector(), builtin_corpus(), only=["bogus"])


def test_robustness_as_dict_shape():
    rep = robustness(_example_detector(), builtin_corpus())
    d = rep.as_dict()
    assert set(d) >= {
        "score", "mutations_total", "mutations_caught",
        "uncaught_baseline", "per_transform", "per_category", "canaries",
    }
    assert isinstance(d["canaries"], list)
    for c in d["canaries"]:
        assert set(c) >= {"id", "category", "score", "missed_transforms"}


def test_robustness_missed_transforms_subset_of_ids():
    rep = robustness(_example_detector(), builtin_corpus())
    for c in rep.canaries:
        assert set(c.missed_transforms) <= set(TRANSFORM_IDS)


def test_canary_score_one_when_no_mutations():
    rep = robustness(lambda s: True, builtin_corpus())
    for c in rep.canaries:
        if c.mutations_total == 0:
            assert c.score == 1.0


# ===========================================================================
# diagnostics
# ===========================================================================
def test_diagnose_example_has_no_dead_or_overbroad():
    diag = diagnose_ruleset(load_ruleset(EXAMPLE_RULES), builtin_corpus())
    assert diag.dead_rules == []
    assert diag.overbroad_rules == []


def test_diagnose_every_rule_present():
    rules = load_ruleset(EXAMPLE_RULES)
    diag = diagnose_ruleset(rules, builtin_corpus())
    assert {r.id for r in diag.rules} == {r.id for r in rules}


def test_diagnose_overbroad_demo_flags_benign():
    diag = diagnose_ruleset(load_ruleset(OVERBROAD), builtin_corpus())
    assert len(diag.overbroad_rules) >= 1
    # every overbroad rule has at least one benign hit
    for r in diag.overbroad_rules:
        assert r.benign_hits


def test_diagnose_overbroad_specific_rule():
    diag = diagnose_ruleset(load_ruleset(OVERBROAD), builtin_corpus())
    ids = {r.id for r in diag.overbroad_rules}
    assert "sqli-apostrophe" in ids


def test_diagnose_dead_rule_detected():
    rules = load_ruleset(EXAMPLE_RULES)
    # append a rule that cannot match anything in the corpus
    from wafproof.detector import Rule
    rules.append(Rule("zzz-dead", "xss", "THIS_LITERAL_NEVER_APPEARS_XYZ", 0))
    diag = diagnose_ruleset(rules, builtin_corpus())
    assert "zzz-dead" in {r.id for r in diag.dead_rules}


def test_diagnose_redundant_pair_detected():
    from wafproof.detector import Rule
    # two rules that match the same single malicious entry and nothing benign
    rules = [
        Rule("a", "xss", "<\\s*script\\b", 0),
        Rule("b", "xss", "script>alert", 0),
    ]
    diag = diagnose_ruleset(rules, builtin_corpus())
    pairs = {frozenset(p) for p in diag.redundant_pairs}
    # both fire only on xss-script-tag among malicious entries, neither on benign
    a = next(r for r in diag.rules if r.id == "a")
    b = next(r for r in diag.rules if r.id == "b")
    if set(a.malicious_hits) == set(b.malicious_hits) and not a.benign_hits and not b.benign_hits:
        assert frozenset({"a", "b"}) in pairs


def test_diagnose_no_redundancy_when_benign_hit():
    from wafproof.detector import Rule
    # identical match-sets but one also hits a benign entry -> not redundant
    rules = [
        Rule("x", "sqli", "'", 0),   # apostrophe: matches malicious + benign O'Brien
        Rule("y", "sqli", "'", 0),
    ]
    diag = diagnose_ruleset(rules, builtin_corpus())
    # both are overbroad (hit benign), so they are excluded from redundancy
    assert diag.redundant_pairs == []


def test_diagnose_hit_ledger_counts():
    diag = diagnose_ruleset(load_ruleset(EXAMPLE_RULES), builtin_corpus())
    for r in diag.rules:
        assert r.total_hits == len(r.malicious_hits) + len(r.benign_hits)


def test_diagnose_as_dict_shape():
    diag = diagnose_ruleset(load_ruleset(OVERBROAD), builtin_corpus())
    d = diag.as_dict()
    assert set(d) >= {
        "rule_count", "dead_rule_count", "overbroad_rule_count",
        "redundant_pair_count", "rules", "dead_rules", "overbroad_rules",
        "redundant_pairs",
    }
    assert d["overbroad_rule_count"] == len(d["overbroad_rules"])


def test_diagnose_from_rules_returns_detector():
    rules = load_ruleset(EXAMPLE_RULES)
    diag, detector = diagnose_from_rules(rules, builtin_corpus())
    assert callable(detector)
    assert detector("<script>alert(1)</script>") is True
    assert len(diag.rules) == len(rules)


def test_diagnose_empty_corpus_all_dead():
    diag = diagnose_ruleset(load_ruleset(EXAMPLE_RULES), [])
    assert len(diag.dead_rules) == len(diag.rules)
