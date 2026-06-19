"""Tests for the built-in corpus and corpus validation."""

import pytest

from wafproof.corpus import (
    CATEGORIES,
    builtin_corpus,
    categories,
    validate_corpus,
)


def test_builtin_corpus_nonempty():
    corpus = builtin_corpus()
    assert len(corpus) >= 20


def test_builtin_corpus_ids_unique():
    corpus = builtin_corpus()
    ids = [e["id"] for e in corpus]
    assert len(ids) == len(set(ids))


def test_builtin_corpus_labels_valid():
    for e in builtin_corpus():
        assert e["label"] in {"malicious", "benign"}


def test_builtin_corpus_has_both_labels_per_category():
    corpus = builtin_corpus()
    for cat in CATEGORIES:
        labels = {e["label"] for e in corpus if e["category"] == cat}
        assert "malicious" in labels, f"{cat} has no malicious canary"
        assert "benign" in labels, f"{cat} has no benign look-alike"


def test_builtin_corpus_validates():
    # Should not raise.
    validate_corpus(builtin_corpus())


def test_categories_helper():
    cats = categories(builtin_corpus())
    assert set(cats) == set(CATEGORIES)


def test_validate_rejects_missing_field():
    with pytest.raises(ValueError, match="missing field"):
        validate_corpus([{"id": "a", "category": "x", "label": "benign"}])


def test_validate_rejects_bad_label():
    with pytest.raises(ValueError, match="invalid label"):
        validate_corpus(
            [{"id": "a", "category": "x", "label": "evil", "text": "t"}]
        )


def test_validate_rejects_duplicate_id():
    entries = [
        {"id": "a", "category": "x", "label": "benign", "text": "t1"},
        {"id": "a", "category": "x", "label": "benign", "text": "t2"},
    ]
    with pytest.raises(ValueError, match="duplicate corpus id"):
        validate_corpus(entries)


def test_validate_rejects_non_string_text():
    with pytest.raises(ValueError, match="must be a string"):
        validate_corpus(
            [{"id": "a", "category": "x", "label": "benign", "text": 5}]
        )


def test_validate_normalizes_note_default():
    out = validate_corpus(
        [{"id": "a", "category": "x", "label": "benign", "text": "t"}]
    )
    assert out[0]["note"] == ""
