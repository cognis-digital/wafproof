"""Tests for the semantics-preserving mutation catalog.

Each transform must (a) actually change the string when it applies, (b) leave it
unchanged when it cannot apply (a no-op the caller can drop), and (c) preserve
the property that makes the mutation equivalent to the original in the threat
model that matters (e.g. URL-decoding round-trips back to the source bytes).
"""

import urllib.parse

import pytest

from wafproof import mutate as M
from wafproof.mutate import (
    TRANSFORM_IDS,
    Mutation,
    mutate,
    transforms,
    t_case_toggle,
    t_double_url_encode,
    t_insert_sql_comments,
    t_null_byte,
    t_redundant_slashes,
    t_trailing_padding,
    t_url_encode,
    t_url_encode_sparse,
    t_whitespace_substitution,
)


# --- catalog shape ---------------------------------------------------------
def test_catalog_nonempty():
    assert len(transforms()) >= 9


def test_transform_ids_unique():
    assert len(TRANSFORM_IDS) == len(set(TRANSFORM_IDS))


def test_transform_ids_match_catalog():
    assert TRANSFORM_IDS == tuple(name for name, _, _ in transforms())


def test_each_catalog_entry_is_callable_with_note():
    for name, fn, note in transforms():
        assert isinstance(name, str) and name
        assert callable(fn)
        assert isinstance(note, str) and note


# --- url-encode ------------------------------------------------------------
def test_url_encode_changes_and_roundtrips():
    src = "<script>alert(1)</script>"
    out = t_url_encode(src)
    assert out != src
    assert "%" in out
    assert urllib.parse.unquote(out) == src


def test_url_encode_decodes_to_original_for_all_specials():
    for src in ["' OR '1'='1", "../../etc/passwd", "127.0.0.1; id"]:
        assert urllib.parse.unquote(t_url_encode(src)) == src


def test_url_encode_sparse_only_encodes_structural_chars():
    src = "<script>"
    out = t_url_encode_sparse(src)
    assert out != src
    # letters left intact, angle brackets encoded
    assert "script" in out
    assert "%3C" in out and "%3E" in out
    assert urllib.parse.unquote(out) == src


def test_url_encode_sparse_noop_on_plain_text():
    src = "hello world"
    assert t_url_encode_sparse(src) == src


def test_double_url_encode_double_decodes():
    src = "<script>"
    once = t_double_url_encode(src)
    assert "%25" in once
    assert urllib.parse.unquote(urllib.parse.unquote(once)) == src


# --- case toggle -----------------------------------------------------------
def test_case_toggle_changes_letters_preserves_lowercased():
    out = t_case_toggle("script")
    assert out != "script"
    assert out.lower() == "script"


def test_case_toggle_noop_on_no_letters():
    src = "127.0.0.1"
    assert t_case_toggle(src) == src


def test_case_toggle_alternates():
    out = t_case_toggle("abcd")
    # first letter lower, then upper, then lower ...
    assert out == "aBcD"


# --- sql comment -----------------------------------------------------------
def test_sql_comment_splices_keyword():
    out = t_insert_sql_comments("UNION SELECT 1")
    assert "/**/" in out
    # removing the comment markers restores a UNION SELECT shape
    assert "UNION".lower() in out.replace("/**/", "").lower()


def test_sql_comment_noop_without_keywords():
    src = "just some prose here"
    assert t_insert_sql_comments(src) == src


def test_sql_comment_case_insensitive():
    assert "/**/" in t_insert_sql_comments("union select")


# --- whitespace ------------------------------------------------------------
def test_whitespace_sub_replaces_spaces():
    out = t_whitespace_substitution("a b c")
    assert " " not in out
    assert "\t" in out or "\n" in out


def test_whitespace_sub_noop_without_spaces():
    src = "no-spaces-here"
    assert t_whitespace_substitution(src) == src


# --- null byte -------------------------------------------------------------
def test_null_byte_inserted_before_last_slash():
    out = t_null_byte("../../etc/passwd")
    assert "\x00" in out
    assert out.replace("\x00", "") == "../../etc/passwd"


def test_null_byte_noop_without_slash():
    assert t_null_byte("passwd") == "passwd"


def test_null_byte_noop_when_slash_is_leading():
    assert t_null_byte("/etc") == "/etc"


# --- redundant slashes -----------------------------------------------------
def test_redundant_slash_changes_traversal():
    out = t_redundant_slashes("../../etc/passwd")
    assert out != "../../etc/passwd"
    assert "//" in out


def test_redundant_slash_noop_without_dotdot():
    assert t_redundant_slashes("assets/logo.png") == "assets/logo.png"


# --- trailing pad ----------------------------------------------------------
def test_trailing_pad_appends():
    out = t_trailing_padding("payload")
    assert out.startswith("payload")
    assert out != "payload"


# --- mutate() orchestration ------------------------------------------------
def test_mutate_drops_noops():
    # a plain word triggers very few transforms; none should be a no-op result
    muts = mutate("<script>alert(1)</script>")
    for m in muts:
        assert isinstance(m, Mutation)
        assert m.text != "<script>alert(1)</script>"
        assert m.transform in TRANSFORM_IDS
        assert m.note


def test_mutate_only_filter():
    muts = mutate("<script>", only=["case-toggle"])
    assert all(m.transform == "case-toggle" for m in muts)
    assert len(muts) == 1


def test_mutate_only_unknown_raises():
    with pytest.raises(ValueError):
        mutate("<script>", only=["not-a-real-transform"])


def test_mutate_only_empty_list_yields_nothing():
    assert mutate("<script>", only=[]) == []


def test_mutate_returns_distinct_transforms():
    muts = mutate("' OR '1'='1; DROP TABLE t")
    ids = [m.transform for m in muts]
    assert len(ids) == len(set(ids))


def test_mutate_plain_text_has_few_or_no_mutations():
    # benign prose with no specials/spaces structure should mutate minimally
    muts = mutate("abc")
    # only case-toggle and trailing-pad can apply
    assert {m.transform for m in muts} <= {"case-toggle", "trailing-pad"}


@pytest.mark.parametrize("src", [
    "<script>alert(1)</script>",
    "' OR '1'='1",
    "../../../../etc/passwd",
    "127.0.0.1; id",
    "value=$(uname -a)",
])
def test_mutate_every_canary_produces_some_mutation(src):
    assert len(mutate(src)) >= 1
