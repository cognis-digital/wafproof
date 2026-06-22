"""SARIF 2.1.0 export for wafproof evaluations.

A wafproof evaluation produces two kinds of actionable finding:

  * a **coverage gap** (FN) -- a malicious canary your detector missed, and
  * a **false alarm** (FP) -- a benign look-alike your detector flagged.

Both are things you want to see surface in CI. SARIF (Static Analysis Results
Interchange Format) 2.1.0 is the standard envelope that GitHub code-scanning,
Azure DevOps, and most security dashboards already ingest, so emitting our
findings as SARIF lets a wafproof run drop straight into an existing pipeline
without bespoke glue.

We map each missed/false-flagged corpus entry to one SARIF ``result`` under one
of two ``rules``:

  * ``wafproof/coverage-gap``  (level ``error``)   for false negatives
  * ``wafproof/false-alarm``   (level ``warning``) for false positives

The corpus *category* (xss, sqli, ...) is carried as a result property and a
partial fingerprint so findings stay stable and groupable across runs. This is a
reporting transform only: no traffic is generated or sent anywhere.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from . import __version__

if TYPE_CHECKING:  # pragma: no cover
    from .metrics import Evaluation

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemas/sarif-schema-2.1.0.json"
)

_RULES = {
    "FN": {
        "id": "wafproof/coverage-gap",
        "name": "DetectionCoverageGap",
        "level": "error",
        "shortDescription": "Detector missed a known-malicious canary",
        "fullDescription": (
            "The detector under test did not flag a corpus entry labeled "
            "malicious. This is a false negative: a coverage gap where a "
            "known-bad input would slip through."
        ),
    },
    "FP": {
        "id": "wafproof/false-alarm",
        "name": "BenignFalseAlarm",
        "level": "warning",
        "shortDescription": "Detector flagged a benign look-alike",
        "fullDescription": (
            "The detector under test flagged a corpus entry labeled benign. "
            "This is a false positive: legitimate traffic that would be "
            "wrongly blocked."
        ),
    },
}


def _fingerprint(outcome: str, category: str, eid: str) -> str:
    """A stable partial fingerprint so the same finding dedupes across runs."""
    h = hashlib.sha256(f"{outcome}:{category}:{eid}".encode("utf-8")).hexdigest()
    return h[:16]


def _rule_descriptors() -> list[dict]:
    out = []
    for spec in _RULES.values():
        out.append(
            {
                "id": spec["id"],
                "name": spec["name"],
                "shortDescription": {"text": spec["shortDescription"]},
                "fullDescription": {"text": spec["fullDescription"]},
                "defaultConfiguration": {"level": spec["level"]},
                "properties": {"tags": ["security", "detection-quality"]},
            }
        )
    return out


def _result_for(entry) -> dict:
    """Build one SARIF result for a single FN/FP EntryResult."""
    spec = _RULES[entry.outcome]
    rule_id = spec["id"]
    rule_index = list(_RULES).index(entry.outcome)
    if entry.outcome == "FN":
        message = (
            f"Missed malicious canary [{entry.category}] {entry.id!r}: the "
            f"detector should have flagged this but did not."
        )
        artifact_uri = f"corpus/{entry.category}/{entry.id}#malicious"
    else:
        message = (
            f"False alarm on benign entry [{entry.category}] {entry.id!r}: the "
            f"detector flagged legitimate-looking input."
        )
        artifact_uri = f"corpus/{entry.category}/{entry.id}#benign"
    return {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": spec["level"],
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_uri,
                        "uriBaseId": "CORPUS",
                    }
                },
                "logicalLocations": [
                    {"name": entry.id, "kind": "member"}
                ],
            }
        ],
        "partialFingerprints": {
            "wafproofCanaryId/v1": _fingerprint(
                entry.outcome, entry.category, entry.id
            )
        },
        "properties": {
            "category": entry.category,
            "label": entry.label,
            "outcome": entry.outcome,
            "canaryId": entry.id,
        },
    }


def evaluation_to_sarif(ev: "Evaluation", *, tool_uri: str | None = None) -> dict:
    """Convert an Evaluation into a SARIF 2.1.0 log dict.

    Only false negatives and false positives become results; correctly handled
    entries (TP/TN) are not findings. The metrics summary is attached to
    ``runs[0].properties`` so a dashboard can chart recall/FPR over time.
    """
    results = [
        _result_for(e) for e in ev.entries if e.outcome in ("FN", "FP")
    ]
    driver = {
        "name": "wafproof",
        "informationUri": tool_uri or "https://github.com/cognis-digital/wafproof",
        "version": __version__,
        "organization": "Cognis Digital",
        "rules": _rule_descriptors(),
    }
    run = {
        "tool": {"driver": driver},
        "results": results,
        "columnKind": "utf16CodeUnits",
        "properties": {
            "metrics": ev.overall.as_dict(),
            "perCategory": {
                cat: c.as_dict() for cat, c in sorted(ev.per_category.items())
            },
        },
    }
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }
