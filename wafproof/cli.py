"""Command-line interface for wafproof.

Subcommands:
    run     evaluate a detector against the corpus and print a metrics table
    corpus  list the labeled corpus (optionally filtered by category)
    report  evaluate and apply a pass/fail gate on recall (CI use)

wafproof is a defensive measurement tool. It does not send traffic anywhere; it
only feeds local labeled strings through a detector you supply and counts hits.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .corpus import builtin_corpus, validate_corpus
from .detector import (
    RulesetError,
    load_callable,
    load_ruleset,
    ruleset_detector,
)
from .metrics import Evaluation, evaluate
from .sarif import evaluation_to_sarif


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _load_corpus(custom_path: str | None) -> list[dict]:
    if custom_path:
        p = Path(custom_path)
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise SystemExit(f"error: corpus file not found: {p}")
        except json.JSONDecodeError as exc:
            raise SystemExit(f"error: corpus {p} is not valid JSON: {exc}")
        if isinstance(raw, dict) and "entries" in raw:
            raw = raw["entries"]
        if not isinstance(raw, list):
            raise SystemExit(
                "error: custom corpus must be a list of entries or an object "
                "with an 'entries' list"
            )
        try:
            return validate_corpus(raw)
        except ValueError as exc:
            raise SystemExit(f"error: {exc}")
    return builtin_corpus()


def _build_detector(args):
    """Construct the detector from --rules or --callable. Returns (detector, rules)."""
    if bool(args.rules) == bool(args.callable):
        raise SystemExit("error: supply exactly one of --rules or --callable")
    if args.rules:
        try:
            rules = load_ruleset(args.rules)
        except RulesetError as exc:
            raise SystemExit(f"error: {exc}")
        return ruleset_detector(rules), rules
    try:
        return load_callable(args.callable), None
    except (ValueError, ImportError) as exc:
        raise SystemExit(f"error: {exc}")


def _fmt_pct(value: float) -> str:
    return f"{value * 100:6.2f}%"


def _write_sarif(ev: Evaluation, dest: str) -> None:
    """Write a SARIF 2.1.0 log of the evaluation's FN/FP findings.

    ``dest`` of '-' writes to stdout; any other value is a file path.
    """
    doc = json.dumps(evaluation_to_sarif(ev), indent=2)
    if dest == "-":
        print(doc)
    else:
        Path(dest).write_text(doc + "\n", encoding="utf-8")


def _print_table(ev: Evaluation) -> None:
    o = ev.overall
    print("Detection evaluation")
    print("=" * 60)
    print(f"  corpus entries : {o.total}")
    print(f"  TP={o.tp}  FP={o.fp}  FN={o.fn}  TN={o.tn}")
    print()
    print(f"  detection rate (recall) : {_fmt_pct(o.recall)}")
    print(f"  precision               : {_fmt_pct(o.precision)}")
    print(f"  F1                      : {_fmt_pct(o.f1)}")
    print(f"  false-positive rate     : {_fmt_pct(o.false_positive_rate)}")
    print(f"  accuracy                : {_fmt_pct(o.accuracy)}")
    print()
    print("Per category")
    print("-" * 60)
    header = f"  {'category':<20}{'recall':>9}{'prec':>9}{'fpr':>9}{'n':>6}"
    print(header)
    for cat, c in sorted(ev.per_category.items()):
        print(
            f"  {cat:<20}{c.recall * 100:8.1f}%{c.precision * 100:8.1f}%"
            f"{c.false_positive_rate * 100:8.1f}%{c.total:>6}"
        )
    if ev.false_negatives:
        print()
        print("Missed canaries (FN) -- coverage gaps:")
        for e in ev.false_negatives:
            print(f"  - [{e.category}] {e.id}: {e.text!r}")
    if ev.false_positives:
        print()
        print("False alarms (FP) -- benign look-alikes flagged:")
        for e in ev.false_positives:
            print(f"  - [{e.category}] {e.id}: {e.text!r}")


# ---------------------------------------------------------------------------
# subcommand handlers
# ---------------------------------------------------------------------------
def cmd_run(args) -> int:
    corpus = _load_corpus(args.corpus)
    detector, _ = _build_detector(args)
    ev = evaluate(detector, corpus)
    if getattr(args, "sarif", None):
        _write_sarif(ev, args.sarif)
        if args.sarif != "-" and not args.json:
            print(f"wrote SARIF 2.1.0 report to {args.sarif}")
    if args.json:
        print(json.dumps(ev.as_dict(), indent=2))
    elif not args.sarif or args.sarif != "-":
        _print_table(ev)
    return 0


def cmd_corpus(args) -> int:
    corpus = _load_corpus(args.corpus)
    if args.category:
        corpus = [e for e in corpus if e["category"] == args.category]
        if not corpus:
            raise SystemExit(f"error: no corpus entries in category {args.category!r}")
    if args.json:
        print(json.dumps(corpus, indent=2))
        return 0
    print(f"{len(corpus)} corpus entries")
    print("=" * 70)
    last_cat = None
    for e in corpus:
        if e["category"] != last_cat:
            print(f"\n[{e['category']}]")
            last_cat = e["category"]
        tag = "MAL " if e["label"] == "malicious" else "ben "
        print(f"  {tag}{e['id']:<24} {e['text']!r}")
        if e.get("note"):
            print(f"       -> {e['note']}")
    return 0


def cmd_report(args) -> int:
    corpus = _load_corpus(args.corpus)
    detector, _ = _build_detector(args)
    ev = evaluate(detector, corpus)
    recall = ev.overall.recall
    passed = recall >= args.fail_under

    if getattr(args, "sarif", None):
        _write_sarif(ev, args.sarif)
        if args.sarif != "-" and not args.json:
            print(f"wrote SARIF 2.1.0 report to {args.sarif}")

    if args.json:
        out = ev.as_dict()
        out["gate"] = {
            "metric": "recall",
            "value": round(recall, 6),
            "fail_under": args.fail_under,
            "passed": passed,
        }
        print(json.dumps(out, indent=2))
    else:
        _print_table(ev)
        print()
        status = "PASS" if passed else "FAIL"
        print(
            f"GATE [{status}] recall {recall * 100:.2f}% "
            f"(threshold {args.fail_under * 100:.2f}%)"
        )
    return 0 if passed else 1


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------
def _add_detector_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--rules", metavar="FILE", help="path to a JSON regex ruleset")
    p.add_argument(
        "--callable",
        metavar="SPEC",
        help="Python detector as 'module:function' or 'file.py:function'",
    )
    p.add_argument(
        "--corpus",
        metavar="FILE",
        help="use a custom labeled corpus JSON instead of the built-in one",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wafproof",
        description=(
            "Measure how well your own detection rules catch known-bad inputs "
            "without flagging benign look-alikes. Defensive tooling -- it never "
            "sends traffic anywhere."
        ),
    )
    parser.add_argument("--version", action="version", version=f"wafproof {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="evaluate a detector against the corpus")
    _add_detector_args(p_run)
    p_run.add_argument("--json", action="store_true", help="emit JSON results")
    p_run.add_argument(
        "--sarif",
        metavar="FILE",
        help="also write a SARIF 2.1.0 report of FN/FP findings ('-' for stdout)",
    )
    p_run.set_defaults(func=cmd_run)

    p_corpus = sub.add_parser("corpus", help="list the labeled corpus")
    p_corpus.add_argument(
        "--corpus", metavar="FILE", help="use a custom corpus JSON file"
    )
    p_corpus.add_argument("--category", help="filter to a single category")
    p_corpus.add_argument("--json", action="store_true", help="emit JSON")
    p_corpus.set_defaults(func=cmd_corpus)

    p_report = sub.add_parser(
        "report", help="evaluate and gate on recall (CI coverage check)"
    )
    _add_detector_args(p_report)
    p_report.add_argument(
        "--fail-under",
        type=float,
        default=0.8,
        metavar="X",
        help="exit non-zero if recall is below X (0..1, default 0.8)",
    )
    p_report.add_argument("--json", action="store_true", help="emit JSON results")
    p_report.add_argument(
        "--sarif",
        metavar="FILE",
        help="also write a SARIF 2.1.0 report of FN/FP findings ('-' for stdout)",
    )
    p_report.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "fail_under", None) is not None:
        if not 0.0 <= args.fail_under <= 1.0:
            raise SystemExit("error: --fail-under must be between 0 and 1")
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
