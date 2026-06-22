"""Semantics-preserving evasion transforms for robustness testing.

A regex/WAF rule that matches ``<script>alert(1)</script>`` literally is worth
little if a trivially-equivalent input slips past it. Real attackers do not send
the textbook shape of a payload; they send an *encoded* or *mangled* shape that
the server-side stack decodes back to the same dangerous thing. The classic WAF
failure mode is a rule that catches the canonical canary but misses every common
obfuscation of it.

``mutate`` turns that failure mode into a number. It applies a catalog of
**documented, semantics-preserving** transformations to *your own* malicious
canaries and re-runs them through *your own* detector. The fraction of mutations
the detector still catches is its **evasion-resistance score**: high means the
rule generalizes past the literal string; low means the rule is brittle and an
attacker who knows one trick walks through it.

This is strictly a defensive ruler. Nothing here is sent anywhere. The transforms
are *benign-preserving in the threat model that matters*: a real target that
URL-decodes a query string, lower-cases a tag name, or strips SQL comments would
reconstitute the same attack — which is exactly why your detector must catch the
mutated form too. The point is to measure and close that gap before an attacker
finds it, not to weaponize anything.

Each transform is:
  * **pure** (str -> str), deterministic, and stdlib-only;
  * **documented** with the real bypass class it mirrors and the server-side
    behavior that makes the mutation equivalent to the original;
  * **idempotent-safe**: a transform that cannot meaningfully apply to a given
    string returns the string unchanged, and such no-ops are filtered out so the
    score is never diluted by transforms that did nothing.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Callable

Transform = Callable[[str], str]


@dataclass(frozen=True)
class Mutation:
    """One applied transform: the resulting text plus provenance."""

    transform: str   # the transform id that produced this
    text: str        # the mutated string
    note: str        # why the mutation is equivalent to the original


# ---------------------------------------------------------------------------
# Individual transforms. Each returns the input unchanged when it cannot apply,
# so callers can detect and drop no-ops.
# ---------------------------------------------------------------------------
def t_url_encode(text: str) -> str:
    """Percent-encode every byte (over-encoding).

    Mirrors the oldest WAF bypass there is: a server that URL-decodes the query
    string before using it sees the original bytes, but a rule matching against
    the raw wire form sees only ``%xx`` triplets. Catching this requires either
    decoding first or a rule that tolerates encoding.
    """
    return urllib.parse.quote(text, safe="")


def t_url_encode_sparse(text: str) -> str:
    """Percent-encode only the structurally significant characters.

    Real payloads rarely over-encode everything (that itself looks anomalous);
    they encode just the ``<``, ``'``, ``/``, ``;`` etc. that a naive rule keys
    on, leaving the rest readable. This is the most common real-world shape.
    """
    significant = "<>'\"/;|&()=`%."
    out = []
    changed = False
    for ch in text:
        if ch in significant:
            out.append("%{:02X}".format(ord(ch)))
            changed = True
        else:
            out.append(ch)
    return "".join(out) if changed else text


def t_double_url_encode(text: str) -> str:
    """Encode, then encode the percent signs again (``%`` -> ``%25``).

    Defeats stacks that decode exactly once before the rule runs but decode a
    second time downstream. A frequent gap in multi-tier proxies.
    """
    once = urllib.parse.quote(text, safe="")
    return once.replace("%", "%25")


def t_case_toggle(text: str) -> str:
    """Alternate the case of ASCII letters (``ScRiPt``).

    HTML tag names, SQL keywords, and many shell builtins are case-insensitive
    on the server but a case-sensitive regex (one written without the ``i``
    flag) will miss the mixed-case form. This transform surfaces missing-flag
    bugs immediately.
    """
    out = []
    upper = False
    changed = False
    for ch in text:
        if ch.isalpha():
            new = ch.upper() if upper else ch.lower()
            if new != ch:
                changed = True
            out.append(new)
            upper = not upper
        else:
            out.append(ch)
    return "".join(out) if changed else text


def t_insert_sql_comments(text: str) -> str:
    """Insert inline SQL comments (``/**/``) between keyword characters.

    MySQL and friends treat ``/**/`` as whitespace, so ``UN/**/ION`` executes as
    ``UNION``. A rule matching the bare keyword ``\\bunion\\b`` is blind to it.
    Applied only between letters of recognizable SQL keywords so the result stays
    a valid, equivalent statement shape.
    """
    keywords = ("union", "select", "drop", "insert", "update", "delete", "or", "and")
    result = text
    changed = False
    for kw in keywords:
        # case-insensitive whole-keyword search; split the first occurrence
        m = re.search(kw, result, re.IGNORECASE)
        if m:
            s, e = m.span()
            word = result[s:e]
            mid = len(word) // 2
            spliced = word[:mid] + "/**/" + word[mid:]
            result = result[:s] + spliced + result[e:]
            changed = True
    return result if changed else text


def t_whitespace_substitution(text: str) -> str:
    """Swap ASCII spaces for tabs / newlines (and SQL ``/**/`` is handled above).

    Regexes that hard-code a literal space (`` ``) instead of ``\\s`` miss the
    same payload delivered with a tab or newline, which most parsers treat as
    equivalent token separators.
    """
    if " " not in text:
        return text
    # alternate tab and newline so we exercise both
    out = []
    nl = False
    for ch in text:
        if ch == " ":
            out.append("\n" if nl else "\t")
            nl = not nl
        else:
            out.append(ch)
    return "".join(out)


def t_null_byte(text: str) -> str:
    """Insert a NUL byte before a path/extension boundary.

    The classic ``../../etc/passwd%00.png`` trick: languages with C-string
    semantics truncate at the NUL, so a suffix-allowlist check passes but the
    file actually opened is the pre-NUL path. Inserted before the last ``/`` so
    traversal payloads keep their structure.
    """
    idx = text.rfind("/")
    if idx <= 0:
        return text
    return text[:idx] + "\x00" + text[idx:]


def t_redundant_slashes(text: str) -> str:
    """Collapse-resistant path noise: ``..//..///`` and ``.././``.

    Path normalizers differ on how they fold repeated and mixed separators; a
    rule that matches exactly ``(\\.\\./){2,}`` misses ``..//../`` even though
    the OS resolves both to the same parent walk.
    """
    if "../" not in text:
        return text
    return text.replace("../", "..//", 1).replace("../", ".././", 1)


def t_trailing_padding(text: str) -> str:
    """Append benign padding after the payload.

    Anchored rules (those ending in ``$`` or written to match the whole field)
    miss a payload with trailing junk. Unanchored rules should be unaffected —
    which is the point: this transform tells anchored-rule bugs apart from
    healthy substring rules.
    """
    return text + "/*pad*/ "


# ---------------------------------------------------------------------------
# The catalog. Order is stable so reports and tests are deterministic.
# ---------------------------------------------------------------------------
_CATALOG: tuple[tuple[str, Transform, str], ...] = (
    ("url-encode", t_url_encode,
     "server URL-decodes the query string back to the original bytes"),
    ("url-encode-sparse", t_url_encode_sparse,
     "only the structural metacharacters are encoded; decodes to the same input"),
    ("double-url-encode", t_double_url_encode,
     "two decode passes across proxy tiers reconstitute the payload"),
    ("case-toggle", t_case_toggle,
     "tag names / SQL keywords / shell builtins are case-insensitive on the server"),
    ("sql-comment", t_insert_sql_comments,
     "MySQL treats /**/ as whitespace, so UN/**/ION executes as UNION"),
    ("whitespace-sub", t_whitespace_substitution,
     "tabs and newlines are token separators equivalent to spaces"),
    ("null-byte", t_null_byte,
     "C-string truncation at NUL changes the resolved path after an extension check"),
    ("redundant-slash", t_redundant_slashes,
     "path normalizers fold ..// and ../.../ to the same parent walk"),
    ("trailing-pad", t_trailing_padding,
     "trailing junk defeats anchored rules but not substring rules"),
)

TRANSFORM_IDS: tuple[str, ...] = tuple(name for name, _, _ in _CATALOG)


def transforms() -> tuple[tuple[str, Transform, str], ...]:
    """Return the full transform catalog (id, fn, note)."""
    return _CATALOG


def mutate(text: str, *, only: list[str] | None = None) -> list[Mutation]:
    """Apply every transform to ``text`` and return the non-trivial mutations.

    A transform that returns the input unchanged (it did not apply) is dropped,
    so the result contains only mutations that actually altered the string. If
    ``only`` is given, restrict to those transform ids (unknown ids raise).
    """
    if only is not None:
        unknown = set(only) - set(TRANSFORM_IDS)
        if unknown:
            raise ValueError(f"unknown transform id(s): {sorted(unknown)}")
    out: list[Mutation] = []
    for name, fn, note in _CATALOG:
        if only is not None and name not in only:
            continue
        mutated = fn(text)
        if mutated != text:
            out.append(Mutation(transform=name, text=mutated, note=note))
    return out
