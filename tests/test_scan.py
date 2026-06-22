"""Tests for the passive (offline) scan module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wafproof.detector import load_ruleset, ruleset_detector
from wafproof.scan import (
    INPUT_FORMATS,
    ScanItem,
    load_input,
    load_input_file,
    scan_items,
)

FIXTURES = Path(__file__).parent / "fixtures"
RULES = Path(__file__).parent.parent / "examples" / "rules.json"


@pytest.fixture
def detector_and_rules():
    rules = load_ruleset(str(RULES))
    return ruleset_detector(rules), rules


# ----- format detection ----------------------------------------------------
def test_detect_format_lines():
    assert load_input("a\nb")  # no exception
    items = load_input("hello\nworld")
    assert all(isinstance(i, ScanItem) for i in items)


def test_detect_json_array():
    items = load_input('["a", "b"]')
    assert [i.text for i in items] == ["a", "b"]


def test_detect_har_via_log_key():
    text = json.dumps({"log": {"entries": []}})
    # should parse as HAR (no entries -> no items) without error
    assert load_input(text) == []


def test_input_formats_constant():
    assert set(INPUT_FORMATS) == {"lines", "json", "har"}


# ----- lines ---------------------------------------------------------------
def test_lines_skips_blank_and_comments():
    items = load_input("# comment\n\n<script>\n  \nfoo", fmt="lines")
    texts = [i.text for i in items]
    assert "<script>" in texts
    assert "foo" in texts
    assert "# comment" not in texts


def test_lines_preserves_raw_text():
    items = load_input("  spaced  ", fmt="lines")
    assert items[0].text == "  spaced  "


def test_lines_source_numbering():
    items = load_input("a\nb\nc", fmt="lines")
    assert items[0].source == "line:1"
    assert items[2].source == "line:3"


# ----- json ----------------------------------------------------------------
def test_json_array_of_strings():
    items = load_input('["x", "y", "z"]', fmt="json")
    assert len(items) == 3


def test_json_array_of_objects_text_key():
    items = load_input('[{"id": "a1", "text": "payload"}]', fmt="json")
    assert items[0].id == "a1"
    assert items[0].text == "payload"


def test_json_object_value_key_variants():
    for key in ("value", "input", "payload"):
        items = load_input(json.dumps([{key: "v"}]), fmt="json")
        assert items[0].text == "v"


def test_json_object_missing_text_raises():
    with pytest.raises(ValueError, match="no text"):
        load_input('[{"foo": "bar"}]', fmt="json")


def test_json_non_array_raises():
    with pytest.raises(ValueError, match="must be an array"):
        load_input('{"a": 1}', fmt="json")


def test_json_invalid_raises():
    with pytest.raises(ValueError, match="not valid JSON"):
        load_input("{not json", fmt="json")


def test_json_bad_entry_type_raises():
    with pytest.raises(ValueError, match="must be a string or object"):
        load_input("[123]", fmt="json")


# ----- har -----------------------------------------------------------------
def test_har_extracts_url_query_and_body():
    items = load_input_file(str(FIXTURES / "capture.har"))
    sources = {i.source for i in items}
    assert "har:request-url" in sources
    assert any(s.startswith("har:query:") for s in sources)
    assert "har:post-body" in sources


def test_har_query_value_is_decoded():
    items = load_input_file(str(FIXTURES / "capture.har"))
    q_items = [i for i in items if i.source == "har:query:q"]
    assert q_items
    assert "<script>" in q_items[0].text


def test_har_missing_entries_raises():
    with pytest.raises(ValueError, match="log.entries"):
        load_input('{"log": {}}', fmt="har")


def test_har_invalid_json_raises():
    with pytest.raises(ValueError, match="not valid JSON"):
        load_input("{bad", fmt="har")


def test_har_skips_non_dict_request():
    text = json.dumps({"log": {"entries": [{"foo": 1}, {"request": "nope"}]}})
    assert load_input(text, fmt="har") == []


# ----- loading from file ---------------------------------------------------
def test_load_input_file_missing_raises():
    with pytest.raises(ValueError, match="not found"):
        load_input_file(str(FIXTURES / "nope.txt"))


def test_load_input_file_lines():
    items = load_input_file(str(FIXTURES / "inputs.txt"))
    assert any("<script>" in i.text for i in items)


def test_unknown_format_raises():
    with pytest.raises(ValueError, match="unknown input format"):
        load_input("x", fmt="xml")


# ----- scanning ------------------------------------------------------------
def test_scan_flags_malicious(detector_and_rules):
    det, rules = detector_and_rules
    items = load_input_file(str(FIXTURES / "inputs.txt"))
    report = scan_items(items, det, rules=rules)
    assert report.total == len(items)
    assert len(report.flagged) >= 2  # script + traversal + union


def test_scan_attributes_rules(detector_and_rules):
    det, rules = detector_and_rules
    items = [ScanItem(id="x", text="<script>alert(1)</script>")]
    report = scan_items(items, det, rules=rules)
    assert report.findings[0].flagged
    assert "xss-script-open" in report.findings[0].matched_rules
    assert "xss" in report.findings[0].categories


def test_scan_benign_not_flagged(detector_and_rules):
    det, rules = detector_and_rules
    items = [ScanItem(id="x", text="assets/images/logo.png")]
    report = scan_items(items, det, rules=rules)
    assert not report.findings[0].flagged
    assert report.findings[0].matched_rules == []


def test_scan_without_rules_has_no_attribution(detector_and_rules):
    det, _ = detector_and_rules
    items = [ScanItem(id="x", text="<script>")]
    report = scan_items(items, det, rules=None)
    assert report.findings[0].flagged
    assert report.findings[0].matched_rules == []


def test_scan_report_as_dict(detector_and_rules):
    det, rules = detector_and_rules
    items = [ScanItem(id="x", text="<script>", source="line:1")]
    d = scan_items(items, det, rules=rules).as_dict()
    assert d["mode"] == "passive"
    assert d["total"] == 1
    assert d["flagged_count"] == 1
    assert d["findings"][0]["id"] == "x"


def test_scan_har_pipeline_flags_decoded_query(detector_and_rules):
    det, rules = detector_and_rules
    items = load_input_file(str(FIXTURES / "capture.har"))
    report = scan_items(items, det, rules=rules)
    flagged_sources = {f.source for f in report.flagged}
    assert "har:query:q" in flagged_sources


def test_scan_empty_input():
    from wafproof.detector import ruleset_detector

    det = ruleset_detector(load_ruleset(str(RULES)))
    report = scan_items([], det)
    assert report.total == 0
    assert report.flagged == []
