"""Detection-quality metrics.

We frame "malicious" as the positive class. For a detector run over a labeled
corpus:

    TP  detector flagged a malicious canary        (good)
    FN  detector missed a malicious canary         (a coverage gap)
    FP  detector flagged a benign look-alike        (a false alarm)
    TN  detector left a benign look-alike alone     (good)

From those four counts everything else follows:

    precision = TP / (TP + FP)   how trustworthy a flag is
    recall    = TP / (TP + FN)   how much malicious traffic is caught
                                 (also the detection rate)
    f1        = harmonic mean of precision and recall
    fpr       = FP / (FP + TN)   how often benign traffic is wrongly flagged

All functions guard against division by zero by returning 0.0 for an undefined
ratio, which is the conventional, conservative choice for a CI gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .corpus import validate_corpus

Detector = Callable[[str], bool]


def _safe_div(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


@dataclass
class Counts:
    """The 2x2 confusion counts plus derived ratios."""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.fn + self.tn

    @property
    def precision(self) -> float:
        return _safe_div(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float:
        return _safe_div(self.tp, self.tp + self.fn)

    # detection rate is recall by another name
    @property
    def detection_rate(self) -> float:
        return self.recall

    @property
    def false_positive_rate(self) -> float:
        return _safe_div(self.fp, self.fp + self.tn)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r) / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return _safe_div(self.tp + self.tn, self.total)

    def as_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "total": self.total,
            "precision": round(self.precision, 6),
            "recall": round(self.recall, 6),
            "detection_rate": round(self.detection_rate, 6),
            "false_positive_rate": round(self.false_positive_rate, 6),
            "f1": round(self.f1, 6),
            "accuracy": round(self.accuracy, 6),
        }


@dataclass
class EntryResult:
    """The outcome for a single corpus entry."""

    id: str
    category: str
    label: str
    text: str
    flagged: bool
    outcome: str  # one of: TP, FP, FN, TN


@dataclass
class Evaluation:
    """A full evaluation: overall counts, per-category counts, and per-entry
    outcomes."""

    overall: Counts = field(default_factory=Counts)
    per_category: dict[str, Counts] = field(default_factory=dict)
    entries: list[EntryResult] = field(default_factory=list)

    @property
    def false_negatives(self) -> list[EntryResult]:
        return [e for e in self.entries if e.outcome == "FN"]

    @property
    def false_positives(self) -> list[EntryResult]:
        return [e for e in self.entries if e.outcome == "FP"]

    def as_dict(self) -> dict:
        return {
            "overall": self.overall.as_dict(),
            "per_category": {
                cat: counts.as_dict()
                for cat, counts in sorted(self.per_category.items())
            },
            "entries": [
                {
                    "id": e.id,
                    "category": e.category,
                    "label": e.label,
                    "flagged": e.flagged,
                    "outcome": e.outcome,
                }
                for e in self.entries
            ],
        }


def _classify(label: str, flagged: bool) -> str:
    """Map (label, flagged) -> confusion-cell name. Malicious is positive."""
    is_malicious = label == "malicious"
    if is_malicious and flagged:
        return "TP"
    if is_malicious and not flagged:
        return "FN"
    if not is_malicious and flagged:
        return "FP"
    return "TN"


def _tally(counts: Counts, outcome: str) -> None:
    if outcome == "TP":
        counts.tp += 1
    elif outcome == "FP":
        counts.fp += 1
    elif outcome == "FN":
        counts.fn += 1
    else:
        counts.tn += 1


def evaluate(detector: Detector, corpus: list[dict]) -> Evaluation:
    """Run a detector over a labeled corpus and compute all metrics.

    The corpus is validated first so a malformed entry fails loudly.
    """
    entries = validate_corpus(corpus)
    ev = Evaluation()
    for entry in entries:
        flagged = bool(detector(entry["text"]))
        outcome = _classify(entry["label"], flagged)
        _tally(ev.overall, outcome)
        cat_counts = ev.per_category.setdefault(entry["category"], Counts())
        _tally(cat_counts, outcome)
        ev.entries.append(
            EntryResult(
                id=entry["id"],
                category=entry["category"],
                label=entry["label"],
                text=entry["text"],
                flagged=flagged,
                outcome=outcome,
            )
        )
    return ev
