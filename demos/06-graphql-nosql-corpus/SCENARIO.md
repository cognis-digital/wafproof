# Demo 06 — Beyond the built-ins: NoSQL & GraphQL API corpus

## Situation

wafproof's built-in categories are `xss`, `sqli`, `path-traversal`, and
`command-injection`. But categories are just strings — you can define your own.
This demo proves it by tuning a ruleset for a modern API back-end against two
attack classes the built-in corpus never covers:

- **NoSQL operator injection** — MongoDB-style query operators (`$ne`, `$gt`,
  `$where`, `$regex`) smuggled into a JSON body so a `password` check becomes
  "not null", or a secret is brute-forced one character at a time.
- **GraphQL abuse** — pathologically deep nesting (resolver-exhaustion DoS) and
  alias-based batching (many `login(...)` calls in one request to brute-force
  credentials).

All malicious entries are generic, publicly documented *structural shapes* of
each class — no product-specific exploits, no fabricated identifiers.

## Inputs

- `api-corpus.json` — labeled corpus with two new categories, `nosql` and
  `graphql`, including benign payloads that resemble the attacks (a real
  credential JSON, legitimate two-alias GraphQL).
- `api-rules.json` — a structural ruleset: NoSQL rules match operator *keys*
  (`"$ne":`) that never appear in a legitimate value; GraphQL rules match nesting
  depth and alias fan-out.

## Run it

```bash
wafproof run --rules demos/06-graphql-nosql-corpus/api-rules.json --corpus demos/06-graphql-nosql-corpus/api-corpus.json
```

## What to expect

A clean **100% recall, 0% false-positive rate** across both new categories:

```
category               recall     prec      fpr     n
graphql                100.0%   100.0%     0.0%     4
nosql                  100.0%   100.0%     0.0%     7
```

The operator-key rule catches `{"password": {"$ne": null}}` but leaves the benign
`{"note": "prices range from $4 to $9 greater value"}` alone, because `$9` is a
value, not a `"$..."` JSON key. The alias-fan-out rule catches three batched
`login(...)` calls but ignores two legitimate aliases.

## How to act

Treat this as a worked reference for authoring your own categories. Copy the
shape: write benign payloads that *look* dangerous (the hard test cases), then
tighten rules until both the FN and FP columns are empty. Drop the resulting
ruleset + corpus into the CI gate from demo 05.
