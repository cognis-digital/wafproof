"""Built-in labeled canary corpus.

Every entry here is ORIGINAL, authored by Cognis Digital for the express purpose
of tuning and validating your own detection rules. Canaries are intentionally
short, generic, illustrative patterns -- the kind of thing a WAF or detection
function ought to flag -- paired with benign look-alikes that a well-tuned
detector should leave alone. Nothing here is copied from any payload list or
third-party corpus, and nothing here is meant to be sent anywhere. This is a
ruler, not a weapon.

A corpus entry is a dict with:
    id:       stable unique identifier
    category: one of CATEGORIES
    label:    "malicious" (a canary that SHOULD trip a detector) or
              "benign"    (a look-alike that should NOT trip a detector)
    text:     the test string
    note:     short human description of why it is labeled this way
"""

from __future__ import annotations

from typing import Iterable

CATEGORIES = (
    "xss",
    "sqli",
    "path-traversal",
    "command-injection",
)

# ---------------------------------------------------------------------------
# The corpus. Kept deliberately compact and generic. Each malicious canary is a
# textbook shape of the attack class; each benign entry is a plausible
# false-positive trap.
# ---------------------------------------------------------------------------
_CORPUS: tuple[dict, ...] = (
    # ----- cross-site scripting -------------------------------------------
    {
        "id": "xss-script-tag",
        "category": "xss",
        "label": "malicious",
        "text": "<script>alert(1)</script>",
        "note": "classic inline script tag",
    },
    {
        "id": "xss-img-onerror",
        "category": "xss",
        "label": "malicious",
        "text": '<img src=x onerror=alert(1)>',
        "note": "event-handler attribute on an image element",
    },
    {
        "id": "xss-svg-onload",
        "category": "xss",
        "label": "malicious",
        "text": "<svg/onload=alert(1)>",
        "note": "svg element with onload handler",
    },
    {
        "id": "xss-js-uri",
        "category": "xss",
        "label": "malicious",
        "text": "javascript:alert(document.cookie)",
        "note": "javascript: pseudo-protocol in a link",
    },
    {
        "id": "xss-benign-article",
        "category": "xss",
        "label": "benign",
        "text": "I scripted a short film about an alert dog last summer.",
        "note": "prose containing the words script and alert",
    },
    {
        "id": "xss-benign-code-talk",
        "category": "xss",
        "label": "benign",
        "text": "The onload event fires after images finish loading.",
        "note": "documentation prose mentioning onload",
    },
    {
        "id": "xss-benign-markup-text",
        "category": "xss",
        "label": "benign",
        "text": "Use <strong> and <em> for emphasis in your post.",
        "note": "benign HTML markup with harmless tags",
    },

    # ----- SQL injection ---------------------------------------------------
    {
        "id": "sqli-or-true",
        "category": "sqli",
        "label": "malicious",
        "text": "' OR '1'='1",
        "note": "always-true boolean tautology",
    },
    {
        "id": "sqli-union-select",
        "category": "sqli",
        "label": "malicious",
        "text": "1 UNION SELECT username, password FROM users",
        "note": "union-based column extraction",
    },
    {
        "id": "sqli-comment-bypass",
        "category": "sqli",
        "label": "malicious",
        "text": "admin'--",
        "note": "comment terminator to truncate a query",
    },
    {
        "id": "sqli-stacked-drop",
        "category": "sqli",
        "label": "malicious",
        "text": "1; DROP TABLE sessions;--",
        "note": "stacked query attempting a destructive statement",
    },
    {
        "id": "sqli-benign-name",
        "category": "sqli",
        "label": "benign",
        "text": "O'Brien",
        "note": "legitimate name with an apostrophe",
    },
    {
        "id": "sqli-benign-prose",
        "category": "sqli",
        "label": "benign",
        "text": "Select a union representative or drop by the office.",
        "note": "prose using select, union and drop as ordinary words",
    },
    {
        "id": "sqli-benign-query-desc",
        "category": "sqli",
        "label": "benign",
        "text": "Our report joins the orders and users tables nightly.",
        "note": "documentation referencing table names",
    },

    # ----- path traversal --------------------------------------------------
    {
        "id": "pt-dotdot-etc-passwd",
        "category": "path-traversal",
        "label": "malicious",
        "text": "../../../../etc/passwd",
        "note": "relative traversal to a sensitive unix file",
    },
    {
        "id": "pt-encoded-dotdot",
        "category": "path-traversal",
        "label": "malicious",
        "text": "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "note": "url-encoded traversal sequence",
    },
    {
        "id": "pt-windows-backslash",
        "category": "path-traversal",
        "label": "malicious",
        "text": "..\\..\\..\\windows\\win.ini",
        "note": "backslash traversal on windows paths",
    },
    {
        "id": "pt-benign-relative",
        "category": "path-traversal",
        "label": "benign",
        "text": "assets/images/logo.png",
        "note": "ordinary relative asset path, no traversal",
    },
    {
        "id": "pt-benign-version",
        "category": "path-traversal",
        "label": "benign",
        "text": "Upgrade from 1.2 to 1.3; see the etc/notes folder.",
        "note": "prose with dots and the substring etc but no traversal",
    },
    {
        "id": "pt-benign-parent-once",
        "category": "path-traversal",
        "label": "benign",
        "text": "../README.md",
        "note": "a single legitimate parent reference within a project",
    },

    # ----- command injection ----------------------------------------------
    {
        "id": "ci-semicolon-id",
        "category": "command-injection",
        "label": "malicious",
        "text": "127.0.0.1; id",
        "note": "command chained after a semicolon",
    },
    {
        "id": "ci-pipe-cat-passwd",
        "category": "command-injection",
        "label": "malicious",
        "text": "input | cat /etc/passwd",
        "note": "pipe into a file-read command",
    },
    {
        "id": "ci-backtick-subshell",
        "category": "command-injection",
        "label": "malicious",
        "text": "name=`whoami`",
        "note": "backtick command substitution",
    },
    {
        "id": "ci-dollar-subshell",
        "category": "command-injection",
        "label": "malicious",
        "text": "value=$(uname -a)",
        "note": "dollar-paren command substitution",
    },
    {
        "id": "ci-benign-math",
        "category": "command-injection",
        "label": "benign",
        "text": "total = price * quantity; tax extra",
        "note": "prose using a semicolon as ordinary punctuation",
    },
    {
        "id": "ci-benign-pipe-table",
        "category": "command-injection",
        "label": "benign",
        "text": "Name | Role | Email",
        "note": "a markdown table header using pipes",
    },
    {
        "id": "ci-benign-shell-doc",
        "category": "command-injection",
        "label": "benign",
        "text": "Run uname to print the kernel version.",
        "note": "documentation mentioning a command name in prose",
    },
)


def builtin_corpus() -> list[dict]:
    """Return a fresh copy of the built-in labeled corpus."""
    return [dict(entry) for entry in _CORPUS]


def validate_corpus(entries: Iterable[dict]) -> list[dict]:
    """Validate and normalize a list of corpus entries.

    Raises ValueError on malformed input. Returns the validated list.
    """
    required = {"id", "category", "label", "text"}
    valid_labels = {"malicious", "benign"}
    seen_ids: set[str] = set()
    out: list[dict] = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"corpus entry #{i} is not an object")
        missing = required - entry.keys()
        if missing:
            raise ValueError(
                f"corpus entry #{i} missing field(s): {', '.join(sorted(missing))}"
            )
        eid = str(entry["id"])
        if eid in seen_ids:
            raise ValueError(f"duplicate corpus id: {eid!r}")
        seen_ids.add(eid)
        label = str(entry["label"])
        if label not in valid_labels:
            raise ValueError(
                f"corpus entry {eid!r} has invalid label {label!r} "
                f"(expected one of {sorted(valid_labels)})"
            )
        if not isinstance(entry["text"], str):
            raise ValueError(f"corpus entry {eid!r} text must be a string")
        out.append(
            {
                "id": eid,
                "category": str(entry["category"]),
                "label": label,
                "text": entry["text"],
                "note": str(entry.get("note", "")),
            }
        )
    return out


def categories(entries: Iterable[dict]) -> list[str]:
    """Return the sorted unique set of categories present in entries."""
    return sorted({e["category"] for e in entries})
