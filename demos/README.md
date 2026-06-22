# wafproof demos

Each subdirectory is a self-contained, real-use-case scenario: a realistic input
file in wafproof's own format (a ruleset, a labeled corpus, or a callable
detector) plus a `SCENARIO.md` that explains where the data came from, the exact
command to run, what output to expect, and how to act on it. Every demo is
verified to actually produce the output its `SCENARIO.md` describes.

| # | demo | shows |
|---|------|-------|
| 01 | [tighten-overbroad-rule](01-tighten-overbroad-rule/) | a legacy keyword blocklist false-blocks the surname `O'Brien`; measure the FP, then fix it |
| 02 | [coverage-gap-after-refactor](02-coverage-gap-after-refactor/) | a "simplify the rules" PR silently drops SQLi coverage; the `report` gate fails the merge |
| 03 | [custom-app-traffic-corpus](03-custom-app-traffic-corpus/) | bring your own corpus of real app inputs; surfaces a false alarm the generic corpus hides |
| 04 | [callable-allowlist-detector](04-callable-allowlist-detector/) | evaluate a Python `--callable` validator and see the precision/recall trade-off it makes |
| 05 | [ci-gate-and-sarif](05-ci-gate-and-sarif/) | GitHub Actions: hard recall gate + **SARIF 2.1.0** upload to the Security tab |
| 06 | [graphql-nosql-corpus](06-graphql-nosql-corpus/) | define your own categories: NoSQL operator injection and GraphQL abuse |
| 07 | [jndi-lookup-canary](07-jndi-lookup-canary/) | lookup/expression injection (`${jndi:...}`) including the nested-evasion shape |
| 08 | [regression-sarif-baseline](08-regression-sarif-baseline/) | differential gate: fail only on findings a PR *introduces* vs a SARIF baseline |

## Quick tour

```bash
# 01 — see two false alarms from an over-broad blocklist
wafproof run --rules demos/01-tighten-overbroad-rule/overbroad-rules.json

# 02 — fail a CI gate on a coverage regression (exit 1)
wafproof report --rules demos/02-coverage-gap-after-refactor/simplified-rules.json --fail-under 0.9

# 05 — emit SARIF for code scanning
wafproof run --rules demos/05-ci-gate-and-sarif/candidate-rules.json --sarif -
```

All demos use only original, generic, illustrative canaries authored by Cognis
Digital. wafproof never sends traffic anywhere — it classifies local strings and
counts hits.
