# Demo 08 — Regression gating with a SARIF baseline diff

## Situation

An absolute recall threshold (`--fail-under 0.9`) is a blunt gate: it can't tell
"this PR introduced a brand-new gap" from "this gap has existed for months and
we've accepted it." What you often want is a **differential** gate: *fail only if
this change introduces a finding that wasn't there on `main`.*

wafproof's SARIF export makes this trivial because every finding carries a stable
`partialFingerprints` value, so you can set-diff two reports by fingerprint.

## Inputs

- `v1-baseline-rules.json` — the ruleset on `main` (the curated example; zero
  findings).
- `v2-regressed-rules.json` — the ruleset as a PR would change it (the
  "simplified" SQLi ruleset from demo 02; three new coverage gaps).
- `v1-baseline.sarif`, `v2-regressed.sarif` — committed sample outputs.
- `sarif_diff.py` — a tiny, dependency-free differ.

## Run it

Regenerate the two reports, then diff them:

```bash
wafproof run --rules demos/08-regression-sarif-baseline/v1-baseline-rules.json  --sarif v1.sarif
wafproof run --rules demos/08-regression-sarif-baseline/v2-regressed-rules.json --sarif v2.sarif
python demos/08-regression-sarif-baseline/sarif_diff.py v1.sarif v2.sarif
echo $?    # -> 1
```

## What to expect

The baseline has **0** findings; the candidate has **3**. The differ reports each
new finding by canary id and exits non-zero:

```
REGRESSION error    sqli-comment-bypass
REGRESSION error    sqli-stacked-drop
REGRESSION error    sqli-union-select

3 new finding(s) vs baseline -- failing.
```

Diffing a report against itself prints `No new findings vs baseline.` and exits
`0`.

## How to act

In CI: generate the SARIF for `main` (or download the last accepted baseline as
an artifact), generate it for the PR branch, and run `sarif_diff.py`. The PR is
blocked **only** when it makes things measurably worse — and the output names
exactly which canaries regressed, so the author knows what to restore. When you
intentionally accept a finding, refresh the baseline artifact and it stops
failing.
