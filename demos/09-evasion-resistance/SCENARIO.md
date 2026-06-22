# Demo 09 — Evasion-resistance: 100% recall is not 100% safe

**Goal:** show that a ruleset can score a perfect `run` and still be brittle, and
prove that normalization fixes it — with a number, not a hunch.

## 1. The literal ruleset looks perfect

```bash
wafproof run --rules examples/rules.json
```

100% recall, 0% false-positive rate. Ship it? Not yet.

## 2. Stress it with semantics-preserving mutation

```bash
wafproof evade --rules examples/rules.json
```

Evasion-resistance is only ~48.89%. The `By transform` table shows the rules are
**completely blind to URL-encoding** (`url-encode` 0%, `double-url-encode` 0%):
they match raw bytes, but a real server URL-decodes the query string first, so
`%3Cscript%3E` slips through while `<script>` is blocked.

## 3. Normalize before matching, then re-measure

`normalizing_detector.py` in this folder wraps the same ruleset but URL-decodes
(twice), strips SQL comments, and folds whitespace **before** matching:

```bash
wafproof evade --callable demos/09-evasion-resistance/normalizing_detector.py:detect
```

Evasion-resistance climbs to ~95.56% while `run` still reports 100% recall and
0% FPR. The fix was not "more patterns" — it was normalization, and `evade`
proved it.

## 4. Gate it in CI

```bash
wafproof evade \
  --callable demos/09-evasion-resistance/normalizing_detector.py:detect \
  --fail-under 0.9
```

Exit code 0 (pass). Run the same gate against the un-normalized
`examples/rules.json` and it exits 1 — the build fails if robustness regresses.

## 5. Bonus: who is the weakest rule?

```bash
wafproof diagnose --rules examples/rules.json
```

No dead, overbroad, or redundant rules here — but point `diagnose` at
`demos/01-tighten-overbroad-rule/overbroad-rules.json` and it names the exact
rules flagging benign `O'Brien`.
