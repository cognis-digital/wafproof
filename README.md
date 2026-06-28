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


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ wafproof --version
wafproof 0.1.0
```

```console
$ wafproof --help
usage: wafproof [-h] [--version]
                {run,corpus,report,evade,diagnose,scan,enrich,probe} ...

Measure how well your own detection rules catch known-bad inputs without
flagging benign look-alikes. Defensive tooling -- it never sends traffic
anywhere.

positional arguments:
  {run,corpus,report,evade,diagnose,scan,enrich,probe}
    run                 evaluate a detector against the corpus
    corpus              list the labeled corpus
    report              evaluate and gate on recall (CI coverage check)
    evade               measure evasion-resistance under semantics-preserving
                        mutation
    diagnose            attribute matches to rules; find
                        dead/overbroad/redundant rules
    scan                PASSIVE (offline): run a detector over provided input
                        (file/HAR/JSON)
    enrich              PASSIVE (offline): annotate packages/SBOM with the
                        bundled vuln DB
    probe               ACTIVE (AUTHORIZED USE ONLY, off by default): smoke-
                        test a CONSENTED target's live WAF with detection
                        canaries

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
```

> Blocks above are real `wafproof` output — reproduce them from a clone.

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
"run": {
"detector": "my_detector",
"corpus": [
{"input": "12345", "label": 0},
{"input": "abcde", "label": 1}
],
"results": [
{"input": "12346", "match": true, "rule": "rule_1"},
{"input": "abcdef", "match": false, "rule": null}
]
}
}
```

<!-- cognis:example:end -->

## Passive vs. active modes

`wafproof` has two modes, and the safe one is the default.

**Passive (default — fully offline).** Every command except `probe`
(`run`, `report`, `corpus`, `evade`, `diagnose`, `scan`, `enrich`) is passive:
it reads only local input — a ruleset, a labeled corpus, a request-field dump, a
saved HAR capture, an SBOM — feeds strings through a detector *you* supply, and
counts hits. **No network. Ever.** This is the mode you use day to day.

**Active (`probe`) — AUTHORIZED USE ONLY, off by default.** `probe` is the one
command that touches the network. It sends `wafproof`'s own generic detection
canaries to **a target you own or are explicitly authorized to test** and
records whether that target's *own* WAF blocks them — a defensive smoke test of
*your* perimeter, not an attack. It refuses to run unless **all** of these hold:

- `--authorized` is passed (explicit operator acknowledgement; default OFF),
- a non-empty `--target-allowlist` of in-scope hostnames is given, and the
  target's host is in it (anything else is refused before a byte is sent),
- a positive `--rate-limit` (requests/second, default `1.0`) is enforced so a
  probe can never become a flood.

There are no exploit payloads: the canaries are short, generic, length-capped
strings meant to be *recognized and blocked*. A loud authorized-use banner
prints on every active run. **Only ever point it at systems you are authorized
to test — unauthorized probing may be illegal.**

```bash
# refused — active mode is off by default
wafproof probe --target http://staging.internal/search --target-allowlist staging.internal
# -> error: active probing is disabled by default; pass --authorized ...

# allowed — explicit consent + scope + rate limit, against your own host
wafproof probe --target http://staging.internal/search \
  --authorized --target-allowlist staging.internal --rate-limit 2
```

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

Add `--sarif FILE` (to `run` or `report`) to also emit a **SARIF 2.1.0** report
of every false negative and false positive — see
[SARIF export](#sarif-export-code-scanning) below.

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

### `wafproof evade`

**100% recall on the canaries is not 100% safe.** A rule that catches
`<script>` but misses `%3Cscript%3E` (which the server URL-decodes right back to
`<script>`) is one trick away from useless. `evade` applies a catalog of
documented, *semantics-preserving* mutations — URL-encoding (single and double),
case-toggling, SQL `/**/` comment insertion, whitespace substitution, NUL-byte
truncation, redundant path slashes, trailing padding — to the canaries your
detector already catches, then re-measures. The fraction still caught is its
**evasion-resistance score**, broken down by transform so you see *exactly which
evasion class* your rules are blind to.

```bash
wafproof evade --rules examples/rules.json
wafproof evade --rules my_rules.json --only url-encode,case-toggle
wafproof evade --callable mypkg.detect:fn --fail-under 0.9   # CI gate
```

The shipped `examples/rules.json` scores a perfect `run` but only **~49%**
evasion-resistance — it is blind to URL-encoding. The fix is to *normalize before
matching*; see [`docs/EVASION_AND_DIAGNOSTICS.md`](docs/EVASION_AND_DIAGNOSTICS.md)
and [`demos/09-evasion-resistance/`](demos/09-evasion-resistance/) for the full
walkthrough that lifts the score to ~96% while keeping recall at 100%.

> Strictly defensive: the mutations are applied only to *your own* canaries
> against *your own* detector, locally, to measure and close gaps before an
> attacker finds them. Nothing is sent anywhere.

### `wafproof diagnose`

When precision drops, `run` tells you *that* a benign entry was flagged but not
*which rule* did it. `diagnose` attributes every corpus match back to the
individual regex rule and flags three pathologies:

- **dead** rules that match nothing in the corpus (stale debt, or a missing canary),
- **overbroad** rules that match a *benign* entry (the direct cause of false alarms),
- **redundant** rules with an identical malicious hit-set and no benign hits.

```bash
wafproof diagnose --rules my_rules.json
wafproof diagnose --rules my_rules.json --fail-on-overbroad   # CI gate
wafproof diagnose --rules my_rules.json --fail-on-dead --json
```

### `wafproof scan` (passive, offline)

Where `run`/`report` measure a detector against the *canary corpus*, `scan` runs
it over **input you provide** — request-log fields, a saved HTTP capture, a field
dump — and reports which entries are flagged, attributing each flag to the rule
that fired. Still fully offline. Input format is auto-detected or forced with
`--input-format`:

- `lines` — one candidate per line (blank lines and `#` comments skipped),
- `json` — a JSON array of strings, or of objects with a `text`/`value`/`input`
  field,
- `har` — a HAR 1.2 capture; the request URL, each decoded query value, and the
  textual post body each become a candidate.

```bash
wafproof scan --rules my_rules.json --input requests.log
wafproof scan --rules my_rules.json --input capture.har --json
wafproof scan --callable mypkg:detect --input fields.json --fail-on-flag  # CI gate
```

### `wafproof enrich` (passive, offline)

Annotate package names — or a whole SBOM — with the known vulnerabilities
affecting them, using the **bundled offline vuln database**
(`cognis_vulndb.jsonl.gz`, see below). No network, no API key.

```bash
wafproof enrich --package lodash --package django
wafproof enrich --sbom sbom.cdx.json --json          # CycloneDX or SPDX
wafproof enrich --sbom sbom.cdx.json --fail-on-vuln   # CI gate
```

### `wafproof probe` (ACTIVE — authorized use only, off by default)

Smoke-test a **consented** target's live WAF with `wafproof`'s detection
canaries and report the target's block rate. See
[Passive vs. active modes](#passive-vs-active-modes) for the full safety gate —
`--authorized`, `--target-allowlist`, and a positive `--rate-limit` are all
mandatory, and any host not in scope is refused before a request is sent.

```bash
wafproof probe --target http://staging.internal/search \
  --authorized --target-allowlist staging.internal --rate-limit 2
wafproof probe --target http://localhost:8080/q \
  --authorized --target-allowlist localhost --fail-under 0.9   # CI gate on YOUR host
```

> The active path is the only networked code in `wafproof`. It is a defensive
> verification of your own perimeter. Do not point it at anything you are not
> authorized to test.

## Language ports

The **core check** — compile a regex ruleset, run it over a labeled corpus, and
report `TP/FP/FN/TN` with recall/precision/F1/FPR — is mirrored in four languages
under [`ports/`](ports/) so it drops into non-Python stacks:

| Port | Path | Test command |
|------|------|--------------|
| Go         | [`ports/go/`](ports/go/)       | `go test ./...` |
| Rust       | [`ports/rust/`](ports/rust/)   | `cargo test` |
| TypeScript | [`ports/ts/`](ports/ts/)       | `npm test` |
| Shell      | [`ports/shell/`](ports/shell/) | `bash test_wafproof.sh` |

Each port carries its own tests and is built/tested on GitHub runners by
[`.github/workflows/ports.yml`](.github/workflows/ports.yml). The Python package
remains the reference implementation with the full feature set (evade, diagnose,
scan, enrich, probe, SARIF).

## SARIF export (code scanning)

Both `run` and `report` accept `--sarif FILE` (use `-` for stdout) to write a
**SARIF 2.1.0** log of the evaluation's findings. Each false negative becomes a
`wafproof/coverage-gap` result (level `error`) and each false positive a
`wafproof/false-alarm` result (level `warning`); correctly handled entries are
not findings. The run's recall/precision/FPR are attached under
`runs[0].properties.metrics`, and every result carries a stable
`partialFingerprints` value so dashboards dedupe the same finding across runs.

```bash
wafproof run --rules my_rules.json --sarif wafproof.sarif
wafproof run --rules my_rules.json --sarif -          # stream to stdout
```

SARIF is the standard envelope GitHub code scanning, Azure DevOps, and most
security dashboards already ingest, so a wafproof run drops straight into an
existing pipeline. A ready-to-copy GitHub Actions workflow lives in
[`demos/05-ci-gate-and-sarif/`](demos/05-ci-gate-and-sarif/), and
[`demos/08-regression-sarif-baseline/`](demos/08-regression-sarif-baseline/)
shows a differential gate that fails only on findings a PR *introduces*.

## Demos

The [`demos/`](demos/) directory holds nine self-contained, real-use-case
scenarios — each a realistic input file in wafproof's own format plus a
`SCENARIO.md` (where the data came from, the exact command, expected output, and
how to act). Highlights:

- **[01](demos/01-tighten-overbroad-rule/)** a keyword blocklist false-blocks the
  surname `O'Brien` — measure the FP, then fix it.
- **[02](demos/02-coverage-gap-after-refactor/)** a "simplify the rules" PR
  silently drops SQLi coverage; the `report` gate fails the merge.
- **[03](demos/03-custom-app-traffic-corpus/)** bring your own corpus of real app
  inputs; surfaces a false alarm the generic corpus hides.
- **[04](demos/04-callable-allowlist-detector/)** evaluate a Python `--callable`
  allowlist validator and see the precision/recall trade-off it makes.
- **[05](demos/05-ci-gate-and-sarif/)** GitHub Actions: hard recall gate + SARIF
  upload to the Security tab.
- **[06](demos/06-graphql-nosql-corpus/)** define your own categories: NoSQL
  operator injection and GraphQL abuse.
- **[07](demos/07-jndi-lookup-canary/)** lookup/expression injection
  (`${jndi:...}`) including the nested-evasion shape.
- **[08](demos/08-regression-sarif-baseline/)** a differential gate that fails
  only on findings a PR introduces vs a SARIF baseline.
- **[09](demos/09-evasion-resistance/)** a ruleset with a perfect `run` is only
  ~49% evasion-resistant; normalizing before matching lifts it to ~96% — proved
  with `evade`, gated in CI.

See [`demos/README.md`](demos/README.md) for the full index.

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
│   ├── cli.py             # run / corpus / report / evade / diagnose / scan / enrich / probe
│   ├── corpus.py          # built-in labeled corpus + validation
│   ├── detector.py        # ruleset + callable loaders
│   ├── metrics.py         # TP/FP/FN/TN, precision/recall/F1, per-category
│   ├── mutate.py          # semantics-preserving evasion transforms
│   ├── analyze.py         # evasion-resistance + ruleset diagnostics
│   ├── sarif.py           # SARIF 2.1.0 export of FN/FP findings
│   ├── scan.py            # PASSIVE: scan provided input (lines/JSON/HAR)
│   ├── enrich.py          # PASSIVE: vuln-DB enrichment of packages/SBOMs
│   ├── probe.py           # ACTIVE (gated): authorized live-WAF smoke test
│   ├── vulndb_local.py    # offline loader for the bundled vuln DB
│   └── cognis_vulndb.jsonl.gz   # 262k real vulns, offline
├── ports/                 # Go / Rust / TypeScript / Shell ports of the core check
│   ├── go/  rust/  ts/  shell/
├── examples/
│   └── rules.json         # authored sample ruleset (scores 100% on the corpus)
├── demos/                 # real-use-case scenarios, each with a SCENARIO.md
├── tests/                 # pytest: metrics, eval, gate, SARIF, scan, enrich, probe
├── pyproject.toml
└── .github/workflows/     # ci.yml (Python) + ports.yml (polyglot)
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

## Bundled vulnerability database

Ships `wafproof/cognis_vulndb.jsonl.gz` — **262,351 real vulnerabilities** (OSV
across 7 ecosystems) with detailed metadata; offline stdlib loader
`vulndb_local.VulnDB`, air-gap ready. It is wired into `wafproof enrich`, so a
passive scan of an SBOM or a list of package names is annotated with the known
vulnerabilities affecting them — entirely offline.

```python
from wafproof.vulndb_local import VulnDB
db = VulnDB()
db.count()                      # -> 262351
db.by_package("lodash")         # records affecting lodash
db.by_cve("CVE-2021-44228")     # lookup by CVE/GHSA alias
```
