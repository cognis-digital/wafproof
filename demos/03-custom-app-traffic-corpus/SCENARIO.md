# Demo 03 — Tuning against your own app's traffic (bring-your-own corpus)

## Situation

The built-in corpus is generic. Your application is not. The most valuable test
cases you own are the *real* requests your app sees: the actual payloads your
staging WAF blocked, and — just as important — the legitimate customer inputs it
blocked **by mistake** and generated support tickets.

This demo packages those into a custom corpus and runs your ruleset against it.
The malicious entries are sanitized reproductions of attack shapes seen in
staging request fields (search box, review body, `?file=` download param, a
network-diagnostic "ping host" tool). The benign entries are real,
previously-false-blocked customer inputs (a name with an apostrophe, a review
that happens to say "drop me a line").

## Input

`app-traffic-corpus.json` — a labeled corpus in wafproof's `--corpus` format,
keyed to this one application's request surface.

## Run it

```bash
wafproof run --rules examples/rules.json --corpus demos/03-custom-app-traffic-corpus/app-traffic-corpus.json
```

## What to expect

Recall is 100% (the structural example rules catch every real attack), **but a
real false alarm surfaces** that the generic corpus never exposed:

```
False alarms (FP) -- benign look-alikes flagged:
  - [sqli] review-text-drop: 'Order arrived fast; drop me a line if the size runs small.'
```

The stacked-statement rule `;\s*(drop|delete|...)` fires on the ordinary English
phrase "...fast; drop me a line". That is precisely the kind of app-specific
false positive you only find by testing against *your* traffic.

## How to act

Two valid fixes, depending on where this field is used:

1. Tighten the rule so it requires SQL-statement context, e.g. anchor it to a
   prior quote/identifier rather than any `;` followed by `drop`.
2. If this field is free-text product reviews, scope the SQLi ruleset so it does
   not run on it, and rely on parameterized queries there (the real fix).

Either way, keep `review-text-drop` in your corpus forever so the regression is
caught the next time someone edits that rule. Add every new false-block ticket
here as you triage it.
