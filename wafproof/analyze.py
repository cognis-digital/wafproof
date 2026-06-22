"""Higher-order analyses over a detector and corpus.

Two analyses live here, both built only from primitives already in wafproof
(the corpus, a detector, and the mutation catalog). Neither sends nor fetches
anything.

1. **Robustness / evasion-resistance** (:func:`robustness`)
   For each *malicious* canary the detector currently catches, apply every
   semantics-preserving mutation and re-test. The share of mutations still
   caught is the canary's robustness; averaging over canaries (and grouping by
   category and by transform) tells you *which* evasion class your rules are
   blind to. A rule that catches ``<script>`` but misses ``<ScRiPt>`` scores
   poorly on ``case-toggle`` and you learn exactly which lever to pull.

   Canaries the detector already misses are reported separately as
   ``uncaught_baseline``: there is no robustness to measure for a payload you
   never caught in the first place — that is a plain coverage gap, surfaced by
   ``run``/``report``.

2. **Ruleset diagnostics** (:func:`diagnose_ruleset`)
   Attribute corpus outcomes back to the individual regex rules that produced
   them. This finds:
     * **dead rules** — never match any corpus entry (maintenance debt, or a
       rule whose canary was removed);
     * **overbroad rules** — match one or more *benign* entries (the source of
       false alarms; the single most useful thing to see when precision drops);
     * **redundant rules** — two rules that fire on exactly the same set of
       malicious entries and on no benign entries, so one is removable;
     * a per-rule hit ledger (which malicious / benign ids each rule fires on).

   Diagnostics require a regex ruleset (``--rules``); a black-box ``--callable``
   has no rules to attribute to, so only robustness applies to it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .corpus import validate_corpus
from .detector import Detector, Rule, ruleset_detector
from .mutate import TRANSFORM_IDS, mutate


# ===========================================================================
# Robustness
# ===========================================================================
@dataclass
class CanaryRobustness:
    """Per-canary mutation survival."""

    id: str
    category: str
    text: str
    mutations_total: int
    mutations_caught: int
    missed_transforms: list[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        if self.mutations_total == 0:
            return 1.0
        return self.mutations_caught / self.mutations_total


@dataclass
class RobustnessReport:
    canaries: list[CanaryRobustness] = field(default_factory=list)
    uncaught_baseline: list[str] = field(default_factory=list)  # canary ids
    per_transform: dict[str, dict] = field(default_factory=dict)
    per_category: dict[str, dict] = field(default_factory=dict)

    @property
    def mutations_total(self) -> int:
        return sum(c.mutations_total for c in self.canaries)

    @property
    def mutations_caught(self) -> int:
        return sum(c.mutations_caught for c in self.canaries)

    @property
    def score(self) -> float:
        """Overall evasion-resistance: caught mutations / total mutations."""
        total = self.mutations_total
        return self.mutations_caught / total if total else 1.0

    def as_dict(self) -> dict:
        return {
            "score": round(self.score, 6),
            "mutations_total": self.mutations_total,
            "mutations_caught": self.mutations_caught,
            "uncaught_baseline": list(self.uncaught_baseline),
            "per_transform": {
                t: {
                    "total": d["total"],
                    "caught": d["caught"],
                    "score": round(d["caught"] / d["total"], 6) if d["total"] else 1.0,
                }
                for t, d in sorted(self.per_transform.items())
            },
            "per_category": {
                c: {
                    "total": d["total"],
                    "caught": d["caught"],
                    "score": round(d["caught"] / d["total"], 6) if d["total"] else 1.0,
                }
                for c, d in sorted(self.per_category.items())
            },
            "canaries": [
                {
                    "id": c.id,
                    "category": c.category,
                    "mutations_total": c.mutations_total,
                    "mutations_caught": c.mutations_caught,
                    "score": round(c.score, 6),
                    "missed_transforms": list(c.missed_transforms),
                }
                for c in self.canaries
            ],
        }


def robustness(
    detector: Detector,
    corpus: list[dict],
    *,
    only: list[str] | None = None,
) -> RobustnessReport:
    """Measure how well a detector survives semantics-preserving mutation.

    Only malicious canaries the detector already catches at baseline contribute
    to the score; canaries missed at baseline are listed in
    ``uncaught_baseline``.
    """
    entries = validate_corpus(corpus)
    report = RobustnessReport()
    per_t: dict[str, dict] = {t: {"total": 0, "caught": 0} for t in TRANSFORM_IDS}
    per_c: dict[str, dict] = {}

    for entry in entries:
        if entry["label"] != "malicious":
            continue
        if not detector(entry["text"]):
            report.uncaught_baseline.append(entry["id"])
            continue
        muts = mutate(entry["text"], only=only)
        caught = 0
        missed: list[str] = []
        cat = entry["category"]
        cbucket = per_c.setdefault(cat, {"total": 0, "caught": 0})
        for m in muts:
            hit = bool(detector(m.text))
            per_t[m.transform]["total"] += 1
            cbucket["total"] += 1
            if hit:
                caught += 1
                per_t[m.transform]["caught"] += 1
                cbucket["caught"] += 1
            else:
                missed.append(m.transform)
        report.canaries.append(
            CanaryRobustness(
                id=entry["id"],
                category=cat,
                text=entry["text"],
                mutations_total=len(muts),
                mutations_caught=caught,
                missed_transforms=missed,
            )
        )
    # drop transforms that never applied to any canary so the report is clean
    report.per_transform = {t: d for t, d in per_t.items() if d["total"] > 0}
    report.per_category = per_c
    return report


# ===========================================================================
# Ruleset diagnostics
# ===========================================================================
@dataclass
class RuleStat:
    id: str
    category: str
    pattern: str
    malicious_hits: list[str] = field(default_factory=list)
    benign_hits: list[str] = field(default_factory=list)

    @property
    def total_hits(self) -> int:
        return len(self.malicious_hits) + len(self.benign_hits)

    @property
    def is_dead(self) -> bool:
        return self.total_hits == 0

    @property
    def is_overbroad(self) -> bool:
        return len(self.benign_hits) > 0


@dataclass
class RulesetDiagnosis:
    rules: list[RuleStat] = field(default_factory=list)
    redundant_pairs: list[tuple[str, str]] = field(default_factory=list)

    @property
    def dead_rules(self) -> list[RuleStat]:
        return [r for r in self.rules if r.is_dead]

    @property
    def overbroad_rules(self) -> list[RuleStat]:
        return [r for r in self.rules if r.is_overbroad]

    def as_dict(self) -> dict:
        return {
            "rule_count": len(self.rules),
            "dead_rule_count": len(self.dead_rules),
            "overbroad_rule_count": len(self.overbroad_rules),
            "redundant_pair_count": len(self.redundant_pairs),
            "rules": [
                {
                    "id": r.id,
                    "category": r.category,
                    "pattern": r.pattern,
                    "malicious_hits": list(r.malicious_hits),
                    "benign_hits": list(r.benign_hits),
                    "dead": r.is_dead,
                    "overbroad": r.is_overbroad,
                }
                for r in self.rules
            ],
            "dead_rules": [r.id for r in self.dead_rules],
            "overbroad_rules": [r.id for r in self.overbroad_rules],
            "redundant_pairs": [list(p) for p in self.redundant_pairs],
        }


def diagnose_ruleset(rules: list[Rule], corpus: list[dict]) -> RulesetDiagnosis:
    """Attribute corpus matches to individual rules to find dead / overbroad /
    redundant rules.
    """
    entries = validate_corpus(corpus)
    stats: dict[str, RuleStat] = {
        r.id: RuleStat(id=r.id, category=r.category, pattern=r.pattern)
        for r in rules
    }
    for entry in entries:
        for rule in rules:
            if rule.matches(entry["text"]):
                st = stats[rule.id]
                if entry["label"] == "malicious":
                    st.malicious_hits.append(entry["id"])
                else:
                    st.benign_hits.append(entry["id"])

    diag = RulesetDiagnosis(rules=list(stats.values()))

    # redundant: same malicious hit-set, both clean of benign hits, non-empty.
    rule_list = diag.rules
    for i in range(len(rule_list)):
        a = rule_list[i]
        if a.is_dead or a.benign_hits:
            continue
        a_set = frozenset(a.malicious_hits)
        for j in range(i + 1, len(rule_list)):
            b = rule_list[j]
            if b.is_dead or b.benign_hits:
                continue
            if frozenset(b.malicious_hits) == a_set:
                diag.redundant_pairs.append((a.id, b.id))
    return diag


def diagnose_from_rules(rules: list[Rule], corpus: list[dict]):
    """Convenience: build the ruleset detector and return (diagnosis, detector)."""
    return diagnose_ruleset(rules, corpus), ruleset_detector(rules)
