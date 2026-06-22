#!/usr/bin/env python3
"""Diff two wafproof SARIF reports by stable finding fingerprint.

Usage:
    python sarif_diff.py baseline.sarif candidate.sarif

Exits 1 if the candidate introduces any finding not present in the baseline
(a NEW coverage gap or false alarm) -- handy as a "no regressions vs main" gate
that is stricter than an absolute recall threshold.
"""
from __future__ import annotations

import json
import sys


def _by_fingerprint(path: str) -> dict[str, dict]:
    doc = json.load(open(path, encoding="utf-8"))
    out = {}
    for r in doc["runs"][0]["results"]:
        fp = r["partialFingerprints"]["wafproofCanaryId/v1"]
        out[fp] = r
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip())
        return 2
    base = _by_fingerprint(argv[0])
    cand = _by_fingerprint(argv[1])

    introduced = [cand[k] for k in cand.keys() - base.keys()]
    fixed = [base[k] for k in base.keys() - cand.keys()]

    for r in sorted(fixed, key=lambda r: r["properties"]["canaryId"]):
        print(f"FIXED      {r['level']:<8} {r['properties']['canaryId']}")
    for r in sorted(introduced, key=lambda r: r["properties"]["canaryId"]):
        print(f"REGRESSION {r['level']:<8} {r['properties']['canaryId']}")

    if introduced:
        print(f"\n{len(introduced)} new finding(s) vs baseline -- failing.")
        return 1
    print("\nNo new findings vs baseline.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
