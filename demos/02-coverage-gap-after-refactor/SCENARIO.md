# Demo 02 — Catching a coverage gap after a "simplification" PR

## Situation

A pull request (call it PR #482) lands titled *"consolidate SQLi rules for
performance."* It replaces four SQLi rules with one tautology check, claiming the
others were redundant. The diff looks tidy and the existing unit tests still
pass, because none of them actually exercise union-based, comment-tail, or
stacked-statement injection. Three real attack shapes are now completely
unguarded — and nobody notices until an incident.

This is the regression wafproof's `report` gate exists to stop **at PR time**.

## Input

`simplified-rules.json` — the ruleset as it would look after the merge. Only the
`sqli-tautology` rule survives in the SQLi category.

## Run it

```bash
wafproof report --rules demos/02-coverage-gap-after-refactor/simplified-rules.json --fail-under 0.9
echo $?    # -> 1
```

## What to expect

The gate **fails** with exit code `1`. Overall recall drops to 80%, and the
report names exactly which canaries slipped through:

```
Missed canaries (FN) -- coverage gaps:
  - [sqli] sqli-union-select: '1 UNION SELECT username, password FROM users'
  - [sqli] sqli-comment-bypass: "admin'--"
  - [sqli] sqli-stacked-drop: '1; DROP TABLE sessions;--'

GATE [FAIL] recall 80.00% (threshold 90.00%)
```

The `sqli` row of the per-category table reads 25.0% recall — a 3-out-of-4 miss.

## How to act

In CI this non-zero exit blocks the merge. The reviewer sees the three named
canaries and asks PR #482 to keep the `sqli-union-select`,
`sqli-comment-tail`, and `sqli-stacked-statement` rules (they are in
[`../../examples/rules.json`](../../examples/rules.json)). If the performance
concern is real, the right move is to benchmark the combined regex, not to delete
coverage. Re-run with the full ruleset and the gate passes.
