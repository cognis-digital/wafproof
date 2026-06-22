# Demo 01 — Tightening an over-broad rule

## Situation

Your team shipped a first-generation WAF blocklist years ago. It is a flat list
of keyword matches: a bare apostrophe means "SQL injection", the word `union`
means "SQL injection", and so on. It catches every attack shape in the corpus —
but support keeps escalating tickets from customers who **can't save their own
name**. One of them is named `O'Brien`. Another typed
"Select a union representative or drop by the office" into a feedback box and got
blocked.

You want to prove the false-positive problem with a number before you touch the
rules, then watch the number go to zero after you fix them.

## Input

`overbroad-rules.json` — the legacy ruleset, in wafproof's JSON ruleset format.
The SQLi rules are deliberately written as bare keyword matches (`'`, `union`,
`select`, `drop`).

## Run it

```bash
wafproof run --rules demos/01-tighten-overbroad-rule/overbroad-rules.json
```

## What to expect

Recall stays at 100% (it still catches everything), but the report flags **two
false alarms** in the `sqli` category:

```
False alarms (FP) -- benign look-alikes flagged:
  - [sqli] sqli-benign-name: "O'Brien"
  - [sqli] sqli-benign-prose: 'Select a union representative or drop by the office.'
```

The per-category table shows `sqli` precision dropping to ~66.7% with a 66.7%
false-positive rate. That is your O'Brien bug, made measurable.

## How to act

Replace the keyword rules with the structural rules in
[`../../examples/rules.json`](../../examples/rules.json): match the *shape* of an
injection (`'\s*or\s+'?\d`, `\bunion\b[\s\S]*\bselect\b`, `;\s*(drop|delete|...)`)
instead of a single keyword. Re-run and confirm the FP list is empty:

```bash
wafproof run --rules examples/rules.json
```

Then add `O'Brien` and any other real customer names that got blocked to a
custom corpus (see demo 03) so this regression can never come back.
