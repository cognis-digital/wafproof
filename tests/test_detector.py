"""Tests for ruleset loading/compilation and callable loading."""

import json

import pytest

from wafproof.detector import (
    RulesetError,
    load_callable,
    load_ruleset,
    matching_rules,
    ruleset_detector,
)


def _write(tmp_path, obj, name="rules.json"):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def test_load_ruleset_object_form(tmp_path):
    p = _write(tmp_path, {"rules": [{"id": "r1", "pattern": "abc"}]})
    rules = load_ruleset(p)
    assert len(rules) == 1
    assert rules[0].id == "r1"


def test_load_ruleset_bare_list_form(tmp_path):
    p = _write(tmp_path, [{"id": "r1", "pattern": "abc"}])
    rules = load_ruleset(p)
    assert rules[0].matches("xxabcxx")
    assert not rules[0].matches("nope")


def test_ruleset_detector_matches_any(tmp_path):
    p = _write(
        tmp_path,
        {"rules": [{"id": "a", "pattern": "foo"}, {"id": "b", "pattern": "bar"}]},
    )
    detect = ruleset_detector(load_ruleset(p))
    assert detect("a foo here")
    assert detect("only bar")
    assert not detect("neither")


def test_flags_ignorecase(tmp_path):
    p = _write(tmp_path, {"rules": [{"id": "a", "pattern": "abc", "flags": ["i"]}]})
    rules = load_ruleset(p)
    assert rules[0].matches("ABC")


def test_missing_pattern_raises(tmp_path):
    p = _write(tmp_path, {"rules": [{"id": "a"}]})
    with pytest.raises(RulesetError, match="missing 'pattern'"):
        load_ruleset(p)


def test_invalid_regex_raises(tmp_path):
    p = _write(tmp_path, {"rules": [{"id": "a", "pattern": "([unclosed"}]})
    with pytest.raises(RulesetError, match="invalid regex"):
        load_ruleset(p)


def test_empty_ruleset_raises(tmp_path):
    p = _write(tmp_path, {"rules": []})
    with pytest.raises(RulesetError, match="no rules"):
        load_ruleset(p)


def test_duplicate_rule_id_raises(tmp_path):
    p = _write(
        tmp_path,
        {"rules": [{"id": "x", "pattern": "a"}, {"id": "x", "pattern": "b"}]},
    )
    with pytest.raises(RulesetError, match="duplicate rule id"):
        load_ruleset(p)


def test_unknown_flag_raises(tmp_path):
    p = _write(tmp_path, {"rules": [{"id": "a", "pattern": "x", "flags": ["z"]}]})
    with pytest.raises(RulesetError, match="unknown regex flag"):
        load_ruleset(p)


def test_bad_json_raises(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(RulesetError, match="not valid JSON"):
        load_ruleset(p)


def test_missing_file_raises(tmp_path):
    with pytest.raises(RulesetError, match="not found"):
        load_ruleset(tmp_path / "nope.json")


def test_matching_rules_returns_subset(tmp_path):
    p = _write(
        tmp_path,
        {"rules": [{"id": "a", "pattern": "foo"}, {"id": "b", "pattern": "bar"}]},
    )
    rules = load_ruleset(p)
    hits = matching_rules(rules, "foo only")
    assert [r.id for r in hits] == ["a"]


def test_load_callable_from_file(tmp_path):
    mod = tmp_path / "mydet.py"
    mod.write_text("def detect(s):\n    return 'evil' in s\n", encoding="utf-8")
    detector = load_callable(f"{mod}:detect")
    assert detector("evil payload") is True
    assert detector("safe") is False


def test_load_callable_bad_spec():
    with pytest.raises(ValueError, match="module:function"):
        load_callable("noseparator")


def test_load_callable_missing_attr(tmp_path):
    mod = tmp_path / "m2.py"
    mod.write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no attribute"):
        load_callable(f"{mod}:detect")
