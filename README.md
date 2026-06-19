# wafproof

**Validate your own detection rules against a labeled canary corpus.**

`wafproof` is a small, dependency-free harness that measures how well *your*
detection function or WAF-style regex ruleset catches known-bad inputs **without
flagging benign look-alikes**. It ships a curated, original corpus of short,
generic canary patterns across common categories (XSS, SQL injection, path
traversal, command injection), each paired with plausible benign strings, and
runs them through a detector you supply to compute detection rate, false-positive
rate, precision/recall, and a per-category breakdown.

> **This is a defensive tool.** `wafproof` never sends traffic anywhere and never
> talks to any target. It only feeds local, labeled strings through a detector
> *you* provide and counts the hits. It is a ruler for tuning and regression-
> testing your defenses — not an attack tool. The built-in canaries are
> intentionally short, generic, illustrative shapes of each attack class,
> authored from scratch by Cognis Digital for detection tuning.

License: COCL 1.0

---

## Why

When you write or tighten a WAF rule, a regex blocklist, or a custom detection
function, two things can go wrong and you usually find out in production:

1. **Coverage gaps** — the rule misses an attack shape it should have caught
   (a false negative; low recall / detection rate).
2. **False alarms** — the rule trips on legitimate traffic that merely *looks*
   suspicious (a false positive; e.g. flagging the name `O'Brien` as SQLi).

`wafproof` turns both into a number you can watch over time and gate on in CI.

## Install

```bash
pip install -e .
```

Standard library only, Python 3.10+. Installs a `wafproof` console command.

## Quick start

Evaluate the bundled example ruleset against the built-in corpus:

```bash
wafproof run --rules examples/rules.json
```

```
Detection evaluation
============================================================
  corpus entries : 27
  TP=15  FP=0  FN=0  TN=12

  detection rate (recall) : 100.00%
  precision               : 100.00%
  F1                      : 100.00%
  false-positive rate     :   0.00%
  accuracy                : 100.00%

Per category
------------------------------------------------------------
  category               recall     prec      fpr     n
  command-injection      100.0%   100.0%     0.0%     7
  path-traversal         100.0%   100.0%     0.0%     6
  sqli                   100.0%   100.0%     0.0%     7
  xss                    100.0%   100.0%     0.0%     7
```

The example ruleset is curated to score perfectly on the built-in corpus so you
have a worked reference. Point `--rules` at *your* ruleset and watch the FN/FP
columns light up — those are exactly the entries to investigate.

## Commands

### `wafproof run`

Evaluate a detector and print the metrics table (or `--json`).

```bash
wafproof run --rules my_rules.json
wafproof run --rules my_rules.json --json
wafproof run --callable mypkg.detect:is_malicious
```

Any missed canaries (false negatives) and false alarms (false positives) are
listed by id and category so you know which rule to fix.

### `wafproof corpus`

List the labeled corpus, optionally filtered by category.

```bash
wafproof corpus
wafproof corpus --category sqli
wafproof corpus --json
```

### `wafproof report`

Evaluate and apply a **pass/fail gate on recall** — exits non-zero if detection
coverage falls below a threshold. Drop this into CI to catch coverage
regressions when someone "simplifies" a rule.

```bash
wafproof report --rules my_rules.json --fail-under 0.8
echo $?   # 0 if recall >= 0.8, else 1
```

## Supplying a detector

A *detector* is anything that, given a string, decides "malicious?" (`True`) or
not. `wafproof` accepts two forms — supply exactly one:

### 1. A regex ruleset (`--rules FILE`)

A JSON file with a `rules` array (a bare list of rule objects also works). A
string is flagged if **any** rule's pattern matches. See
[`examples/rules.json`](examples/rules.json) for a complete authored example.

```json
{
  "name": "my-ruleset",
  "rules": [
    { "id": "xss-script-open", "category": "xss",
      "pattern": "<\\s*script\\b", "flags": ["i"] },
    { "id": "sqli-union-select", "category": "sqli",
      "pattern": "\\bunion\\b[\\s\\S]*\\bselect\\b", "flags": ["i"] }
  ]
}
```

Each rule needs a `pattern` (Python `re` syntax). Optional fields: `id`,
`category`, and `flags` (any of `i`/`ignorecase`, `m`/`multiline`,
`s`/`dotall`, `x`/`verbose`). Broken regex or duplicate ids fail loudly at load
time rather than silently never matching.

### 2. A Python callable (`--callable SPEC`)

Reference a function as `module:function` or `path/to/file.py:function`. It
receives the candidate string and returns a truthy value for malicious:

```python
# mydetector.py
def is_malicious(text: str) -> bool:
    return "<script" in text.lower()
```

```bash
wafproof run --callable mydetector.py:is_malicious
```

## Bring your own corpus

The built-in corpus is a starting point. Supply your own labeled strings with
`--corpus FILE` (works with every command). The file is a JSON list of entries
(or an object with an `entries` list):

```json
{
  "entries": [
    { "id": "my-1", "category": "xss", "label": "malicious",
      "text": "<svg/onload=...>", "note": "why this is bad" },
    { "id": "my-2", "category": "xss", "label": "benign",
      "text": "Use <strong> for emphasis", "note": "harmless markup" }
  ]
}
```

`label` must be `malicious` (a canary that *should* be caught) or `benign`
(a look-alike that should *not* be). Add your real near-miss false positives
here — they are the most valuable test cases you have.

## Metrics, defined

The positive class is **malicious**. For a run over the labeled corpus:

| count | meaning |
|-------|---------|
| TP | flagged a malicious canary (good) |
| FN | **missed** a malicious canary (coverage gap) |
| FP | flagged a benign look-alike (false alarm) |
| TN | left a benign look-alike alone (good) |

- **detection rate / recall** = `TP / (TP + FN)` — how much known-bad you catch
- **precision** = `TP / (TP + FP)` — how trustworthy a flag is
- **F1** = harmonic mean of precision and recall
- **false-positive rate** = `FP / (FP + TN)` — how often you cry wolf

Undefined ratios (division by zero) return `0.0`, the conservative choice for a
gate.

## Project layout

```
wafproof/
├── wafproof/
│   ├── __init__.py
│   ├── __main__.py        # python -m wafproof
│   ├── cli.py             # run / corpus / report
│   ├── corpus.py          # built-in labeled corpus + validation
│   ├── detector.py        # ruleset + callable loaders
│   └── metrics.py         # TP/FP/FN/TN, precision/recall/F1, per-category
├── examples/
│   └── rules.json         # authored sample ruleset (scores 100% on the corpus)
├── tests/                 # pytest: metric math, ruleset eval, gate exit codes
├── pyproject.toml
└── .github/workflows/ci.yml
```

## Development

```bash
pip install -e . pytest
python -m pytest
```

On Windows, set `PYTHONUTF8=1` when running the tests.

## Scope and ethics

`wafproof` exists to make defenses measurable. It does not generate, transform,
encode, or transmit attacks; the canaries are deliberately generic, short, and
illustrative — the kind of shape any competent WAF already blocks — and they
live only to be fed through your own detector locally. If you need broader
coverage, author additional canaries that reflect the traffic *your* application
actually sees and add them via `--corpus`.

---

Maintained by **Cognis Digital**.
