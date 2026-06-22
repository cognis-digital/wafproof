# Demo 05 — CI gate + SARIF upload to GitHub code scanning

## Situation

You want detection-rule quality to be a first-class CI signal, the same way you
treat unit tests and linting. Two complementary checks:

- a **hard gate** that blocks a PR when recall drops below a threshold, and
- a **soft report** that publishes every missed canary and false alarm to the
  GitHub **Security tab** so reviewers can see and triage them inline.

wafproof's `--sarif` export (SARIF 2.1.0) is what makes the second half work:
GitHub's `upload-sarif` action ingests it natively, no glue required.

## Inputs

- `candidate-rules.json` — a ruleset opened in a PR. It is mostly good but has
  one over-broad XSS rule (`script` matches anywhere) and is missing the
  Windows-backslash path-traversal rule.
- `workflow.yml` — a ready-to-copy GitHub Actions workflow.
- `wafproof.sarif` — the committed sample output, so you can see the exact
  envelope before running anything.

## Run it

Reproduce the SARIF locally:

```bash
wafproof run --rules demos/05-ci-gate-and-sarif/candidate-rules.json --sarif out.sarif
```

Or stream it to stdout:

```bash
wafproof run --rules demos/05-ci-gate-and-sarif/candidate-rules.json --sarif -
```

## What to expect

The SARIF log contains exactly two results — one of each severity:

| level   | rule                     | finding                                            |
|---------|--------------------------|----------------------------------------------------|
| warning | `wafproof/false-alarm`   | `xss-benign-article` (the over-broad `script` rule) |
| error   | `wafproof/coverage-gap`  | `pt-windows-backslash` (missing `..\\` rule)        |

Run-level `properties.metrics` carries recall / precision / FPR so a dashboard
can chart them over time. Each result has a stable `partialFingerprints` value,
so GitHub dedupes the same finding across runs instead of reopening it.

## How to act

In CI the `upload-sarif` step turns those two results into code-scanning alerts;
the `wafproof report --fail-under 0.95` step then **fails the build** because the
missed `..\\` canary pulls recall under 95%. Fix both: tighten the XSS rule to
`<\s*script\b` and add the `pt-dotdot-backslash` rule from
[`../../examples/rules.json`](../../examples/rules.json). Re-run — the SARIF goes
empty and the gate passes.
