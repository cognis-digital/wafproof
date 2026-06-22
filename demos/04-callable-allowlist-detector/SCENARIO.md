# Demo 04 — Evaluating a Python callable (allowlist validator)

## Situation

Not every detector is a regex blocklist. A very common real pattern is a
*positive validator*: a small function that accepts a field only if it matches a
conservative allowlist, and rejects everything else. This demo ships exactly
that — `is_malicious()` for a **username** field — and points wafproof at it as a
`--callable` detector.

The point is to show two things at once:

1. how to wire an arbitrary Python function into wafproof, and
2. how wafproof exposes the *trade-off* a strict validator makes.

## Input

`detector.py` — a Python module exposing `is_malicious(text) -> bool`. A username
is rejected if it contains characters outside `[A-Za-z0-9 ._'@-]` or carries an
obvious injection marker (`<`, `../`, `$(`, backtick, `;`, `--`, ...).

## Run it

```bash
wafproof run --callable demos/04-callable-allowlist-detector/detector.py:is_malicious
```

## What to expect

Recall is **100%** — an allowlist as tight as this catches every attack shape.
But the false-positive rate is **50%**, and wafproof names every benign entry it
rejected:

```
False alarms (FP) -- benign look-alikes flagged:
  - [xss] xss-benign-markup-text: 'Use <strong> and <em> for emphasis in your post.'
  - [path-traversal] pt-benign-relative: 'assets/images/logo.png'
  - [command-injection] ci-benign-pipe-table: 'Name | Role | Email'
  ...
```

## How to act

This is **not a bug in the validator** — it is the validator working as designed,
shown honestly. A username allowlist *should* reject `assets/images/logo.png` and
a markdown table; those simply aren't usernames. The lesson wafproof drives home
is **scope**: a validator is only "correct" against a corpus of inputs from the
field it guards.

The right next step is to build a username-specific corpus (real usernames as
benign, the injection shapes as malicious — see demo 03) and re-run. Against
*that* corpus this same detector should score near 100% precision. Using the
generic corpus here makes the scoping lesson visible, which is the whole point.
