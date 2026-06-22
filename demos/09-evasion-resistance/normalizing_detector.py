"""A normalizing wrapper around the bundled example ruleset.

Demonstrates the fix for the evasion gap that ``wafproof evade`` surfaces: the
literal ruleset matches raw wire bytes, so URL-encoded / commented / oddly-spaced
payloads slip past even though the server reconstitutes the same attack. This
detector performs the same normalization a hardened WAF would (URL-decode twice,
strip SQL comments, fold whitespace) *before* running the rules.

Used by demo 09 and resolves the ruleset path relative to the repo root so it
works from any working directory. Defensive tooling -- no traffic is sent.
"""

from __future__ import annotations

import re
import urllib.parse
from pathlib import Path

from wafproof.detector import load_ruleset, ruleset_detector

_RULES_PATH = (
    Path(__file__).resolve().parents[2] / "examples" / "rules.json"
)
_base = ruleset_detector(load_ruleset(_RULES_PATH))

_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_WS = re.compile(r"\s+")


def normalize(s: str) -> str:
    """Decode and canonicalize input the way a server-side stack would."""
    for _ in range(2):  # two passes defeats double-encoding
        s = urllib.parse.unquote(s)
    s = _COMMENT.sub(" ", s)   # /**/ -> space (note: turns UN/**/ION into UN ION)
    s = _WS.sub(" ", s)        # fold tabs/newlines back to single spaces
    return s


def detect(text: str) -> bool:
    return _base(normalize(text))
