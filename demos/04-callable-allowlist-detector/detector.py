"""A real-world Python detector for a username field.

Many real detection functions are not regex blocklists at all -- they are small
bits of imperative logic. This one models a common pattern: a *positive*
validator. A username is considered malicious if it contains anything outside a
conservative allowlist of characters, OR if it carries an obvious injection
marker.

Point wafproof at it with::

    wafproof run --callable demos/04-callable-allowlist-detector/detector.py:is_malicious

Note how an allowlist validator achieves a very low false-positive rate on the
benign corpus (plain prose passes) while still catching the structural attack
shapes -- but it WILL miss attacks expressed entirely in allowed characters,
which is exactly the trade-off wafproof makes visible.
"""

from __future__ import annotations

import re

# Characters a username may legitimately contain. Anything else is suspicious.
_ALLOWED = re.compile(r"^[A-Za-z0-9 ._'@-]+$")

# Cheap structural markers that should never appear in a username.
_INJECTION_MARKERS = (
    "<",
    ">",
    "../",
    "..\\",
    "%2e%2e",
    "$(",
    "`",
    "|",
    ";",
    "--",
    "/*",
)


def is_malicious(text: str) -> bool:
    """Return True if the candidate string should be rejected."""
    lowered = text.lower()
    if any(marker in lowered for marker in _INJECTION_MARKERS):
        return True
    # Anything with characters outside the allowlist is rejected.
    if not _ALLOWED.match(text):
        return True
    # Tautology shapes ('... or 1=1) still pass the allowlist, so check them too.
    if re.search(r"'\s*or\s+'?\d", lowered):
        return True
    return False
