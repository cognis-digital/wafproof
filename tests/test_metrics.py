"""Tests for the metric math: TP/FP/FN/TN, precision, recall, F1, per-category."""

import math

import pytest

from wafproof.metrics import Counts, evaluate


def test_counts_perfect_classifier():
    c = Counts(tp=4, fp=0, fn=0, tn=4)
    assert c.total == 8
    assert c.precision == 1.0
    assert c.recall == 1.0
    assert c.detection_rate == 1.0
    assert c.false_positive_rate == 0.0
    assert c.f1 == 1.0
    assert c.accuracy == 1.0


def test_counts_precision_and_recall_math():
    # 3 true positives, 1 false positive, 2 false negatives
    c = Counts(tp=3, fp=1, fn=2, tn=4)
    assert c.precision == pytest.approx(3 / 4)
    assert c.recall == pytest.approx(3 / 5)
    assert c.false_positive_rate == pytest.approx(1 / 5)


def test_f1_is_harmonic_mean():
    c = Counts(tp=3, fp=1, fn=2, tn=4)
    p, r = c.precision, c.recall
    expected = 2 * p * r / (p + r)
    assert c.f1 == pytest.approx(expected)


def test_zero_division_guards_return_zero():
    empty = Counts()
    assert empty.precision == 0.0
    assert empty.recall == 0.0
    assert empty.f1 == 0.0
    assert empty.false_positive_rate == 0.0
    assert empty.accuracy == 0.0


def test_recall_zero_when_all_missed():
    c = Counts(tp=0, fp=0, fn=5, tn=5)
    assert c.recall == 0.0
    assert c.detection_rate == 0.0


def test_evaluate_classifies_each_cell():
    corpus = [
        {"id": "m1", "category": "xss", "label": "malicious", "text": "bad1"},
        {"id": "m2", "category": "xss", "label": "malicious", "text": "bad2"},
        {"id": "b1", "category": "xss", "label": "benign", "text": "ok1"},
        {"id": "b2", "category": "xss", "label": "benign", "text": "ok2"},
    ]

    # flags "bad1" (TP) and "ok1" (FP); misses "bad2" (FN); leaves "ok2" (TN)
    def detector(text):
        return text in {"bad1", "ok1"}

    ev = evaluate(detector, corpus)
    assert ev.overall.tp == 1
    assert ev.overall.fn == 1
    assert ev.overall.fp == 1
    assert ev.overall.tn == 1
    outcomes = {e.id: e.outcome for e in ev.entries}
    assert outcomes == {"m1": "TP", "m2": "FN", "b1": "FP", "b2": "TN"}


def test_evaluate_per_category_breakdown():
    corpus = [
        {"id": "x1", "category": "xss", "label": "malicious", "text": "x-bad"},
        {"id": "s1", "category": "sqli", "label": "malicious", "text": "s-bad"},
        {"id": "s2", "category": "sqli", "label": "benign", "text": "s-ok"},
    ]

    def detector(text):
        return text.endswith("bad")

    ev = evaluate(detector, corpus)
    assert set(ev.per_category) == {"xss", "sqli"}
    assert ev.per_category["xss"].tp == 1
    assert ev.per_category["sqli"].tp == 1
    assert ev.per_category["sqli"].tn == 1
    assert ev.per_category["sqli"].recall == 1.0


def test_evaluate_collects_false_negatives_and_positives():
    corpus = [
        {"id": "m", "category": "c", "label": "malicious", "text": "miss-me"},
        {"id": "b", "category": "c", "label": "benign", "text": "flag-me"},
    ]

    def detector(text):
        return text == "flag-me"

    ev = evaluate(detector, corpus)
    assert [e.id for e in ev.false_negatives] == ["m"]
    assert [e.id for e in ev.false_positives] == ["b"]


def test_as_dict_roundtrip_keys():
    c = Counts(tp=1, fp=1, fn=1, tn=1)
    d = c.as_dict()
    for key in ("tp", "fp", "fn", "tn", "precision", "recall", "f1", "accuracy"):
        assert key in d
    assert math.isclose(d["recall"], 0.5)
