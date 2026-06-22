"""Command-line interface for wafproof.

Subcommands:
    run       evaluate a detector against the corpus and print a metrics table
    corpus    list the labeled corpus (optionally filtered by category)
    report    evaluate and apply a pass/fail gate on recall (CI use)
    evade     measure evasion-resistance under semantics-preserving mutation
    diagnose  attribute matches to rules; find dead/overbroad/redundant rules
    scan      PASSIVE (default, offline): run a detector over provided input
    enrich    PASSIVE (offline): annotate packages/SBOM with the bundled vuln DB
    probe     ACTIVE (authorization-gated, OFF by default): smoke-test a
              CONSENTED target's live WAF with detection canaries

PASSIVE modes (run/report/evade/diagnose/scan/enrich) never touch the network;
they only read local input and feed strings through a detector you supply.

The ACTIVE 'probe' mode is the sole exception and is OFF by default: it requires
--authorized AND a --target-allowlist AND a positive --rate-limit, and refuses
any host not in scope. It is a defensive smoke test of YOUR OWN perimeter.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analyze import diagnose_ruleset, robustness
from .corpus import builtin_corpus, validate_corpus
from .detector import (
    RulesetError,
    load_callable,
    load_ruleset,
    ruleset_detector,
)
from .enrich import enrich_packages, enrich_sbom_file
from .metrics import Evaluation, evaluate
from .mutate import TRANSFORM_IDS
from .probe import (
    AUTHORIZED_USE_BANNER,
    AuthorizationError,
    ScopeError,
    probe_target,
)
from .sarif import evaluation_to_sarif
from .scan import load_input_file, scan_items


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


def _print_robustness(rep) -> None:
    print("Evasion-resistance evaluation")
    print("=" * 60)
    print(f"  mutations applied : {rep.mutations_total}")
    print(f"  mutations caught  : {rep.mutations_caught}")
    print(f"  evasion-resistance: {_fmt_pct(rep.score)}")
    if rep.uncaught_baseline:
        print(
            f"  (excluded {len(rep.uncaught_baseline)} canary(ies) the detector "
            f"misses at baseline -- those are coverage gaps, see 'run')"
        )
    print()
    print("By transform (lower = the evasion class your rules are blind to)")
    print("-" * 60)
    print(f"  {'transform':<20}{'caught':>9}{'total':>9}{'score':>9}")
    for t, d in sorted(rep.per_transform.items(), key=lambda kv: (kv[1]["caught"] / kv[1]["total"] if kv[1]["total"] else 1.0, kv[0])):
        sc = d["caught"] / d["total"] if d["total"] else 1.0
        print(f"  {t:<20}{d['caught']:>9}{d['total']:>9}{sc * 100:8.1f}%")
    print()
    print("By category")
    print("-" * 60)
    print(f"  {'category':<20}{'caught':>9}{'total':>9}{'score':>9}")
    for c, d in sorted(rep.per_category.items()):
        sc = d["caught"] / d["total"] if d["total"] else 1.0
        print(f"  {c:<20}{d['caught']:>9}{d['total']:>9}{sc * 100:8.1f}%")
    weak = [c for c in rep.canaries if c.missed_transforms]
    if weak:
        print()
        print("Brittle canaries (evaded by at least one mutation):")
        for c in weak:
            print(
                f"  - [{c.category}] {c.id}: misses "
                f"{', '.join(c.missed_transforms)}"
            )


def cmd_evade(args) -> int:
    corpus = _load_corpus(args.corpus)
    detector, _ = _build_detector(args)
    only = None
    if args.only:
        only = [t.strip() for t in args.only.split(",") if t.strip()]
    try:
        rep = robustness(detector, corpus, only=only)
    except ValueError as exc:
        raise SystemExit(f"error: {exc}")
    if args.json:
        out = rep.as_dict()
        if args.fail_under is not None:
            out["gate"] = {
                "metric": "evasion_resistance",
                "value": round(rep.score, 6),
                "fail_under": args.fail_under,
                "passed": rep.score >= args.fail_under,
            }
        print(json.dumps(out, indent=2))
    else:
        _print_robustness(rep)
        if args.fail_under is not None:
            passed = rep.score >= args.fail_under
            print()
            print(
                f"GATE [{'PASS' if passed else 'FAIL'}] evasion-resistance "
                f"{rep.score * 100:.2f}% (threshold {args.fail_under * 100:.2f}%)"
            )
    if args.fail_under is not None and rep.score < args.fail_under:
        return 1
    return 0


def _print_diagnosis(diag) -> None:
    print("Ruleset diagnostics")
    print("=" * 60)
    print(f"  rules           : {len(diag.rules)}")
    print(f"  dead rules      : {len(diag.dead_rules)}")
    print(f"  overbroad rules : {len(diag.overbroad_rules)}")
    print(f"  redundant pairs : {len(diag.redundant_pairs)}")
    print()
    print("Per rule")
    print("-" * 60)
    print(f"  {'rule':<26}{'mal':>5}{'ben':>5}  flags")
    for r in diag.rules:
        flags = []
        if r.is_dead:
            flags.append("DEAD")
        if r.is_overbroad:
            flags.append("OVERBROAD")
        print(
            f"  {r.id:<26}{len(r.malicious_hits):>5}{len(r.benign_hits):>5}  "
            f"{' '.join(flags)}"
        )
    if diag.dead_rules:
        print()
        print("Dead rules (match nothing in the corpus -- maintenance debt):")
        for r in diag.dead_rules:
            print(f"  - {r.id}  /{r.pattern}/")
    if diag.overbroad_rules:
        print()
        print("Overbroad rules (flag benign entries -- cause of false alarms):")
        for r in diag.overbroad_rules:
            print(f"  - {r.id}  flags benign: {', '.join(r.benign_hits)}")
    if diag.redundant_pairs:
        print()
        print("Redundant rule pairs (same malicious hit-set, no benign hits):")
        for a, b in diag.redundant_pairs:
            print(f"  - {a}  ==  {b}")


def cmd_diagnose(args) -> int:
    corpus = _load_corpus(args.corpus)
    if not args.rules:
        raise SystemExit(
            "error: diagnose requires --rules (a callable has no rules to "
            "attribute matches to; use 'evade' for black-box robustness)"
        )
    try:
        rules = load_ruleset(args.rules)
    except RulesetError as exc:
        raise SystemExit(f"error: {exc}")
    diag = diagnose_ruleset(rules, corpus)
    if args.json:
        print(json.dumps(diag.as_dict(), indent=2))
    else:
        _print_diagnosis(diag)
    if args.fail_on_dead and diag.dead_rules:
        return 1
    if args.fail_on_overbroad and diag.overbroad_rules:
        return 1
    return 0


# ---------------------------------------------------------------------------
# passive: scan provided input
# ---------------------------------------------------------------------------
def cmd_scan(args) -> int:
    detector, rules = _build_detector(args)
    try:
        items = load_input_file(args.input, fmt=args.input_format)
    except ValueError as exc:
        raise SystemExit(f"error: {exc}")
    report = scan_items(items, detector, rules=rules)
    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        print("Passive scan (offline)")
        print("=" * 60)
        print(f"  items scanned : {report.total}")
        print(f"  flagged       : {len(report.flagged)}")
        if report.flagged:
            print()
            print("Flagged input:")
            for f in report.flagged:
                rules_note = (
                    f"  [{', '.join(f.matched_rules)}]" if f.matched_rules else ""
                )
                print(f"  - {f.id} ({f.source}): {f.text!r}{rules_note}")
        else:
            print()
            print("  no input flagged by the detector")
    if args.fail_on_flag and report.flagged:
        return 1
    return 0


# ---------------------------------------------------------------------------
# passive: vuln-DB enrichment
# ---------------------------------------------------------------------------
def cmd_enrich(args) -> int:
    if bool(args.sbom) == bool(args.package):
        raise SystemExit("error: supply exactly one of --sbom or --package")
    try:
        if args.sbom:
            report = enrich_sbom_file(args.sbom)
        else:
            names = [p.strip() for p in args.package if p.strip()]
            report = enrich_packages(names, ecosystem=args.ecosystem)
    except ValueError as exc:
        raise SystemExit(f"error: {exc}")
    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        print("Offline vuln-DB enrichment")
        print("=" * 60)
        print(f"  packages checked    : {len(report.packages)}")
        print(f"  vulnerable packages : {len(report.vulnerable_packages)}")
        print(f"  total vulns         : {report.total_vulns}")
        if report.vulnerable_packages:
            print()
            for p in report.vulnerable_packages:
                eco = f" ({p.ecosystem})" if p.ecosystem else ""
                print(f"  - {p.package}{eco}: {p.count} vuln(s)")
                for vid in p.vuln_ids[:8]:
                    print(f"      {vid}")
                if p.count > 8:
                    print(f"      ... and {p.count - 8} more")
    if args.fail_on_vuln and report.total_vulns:
        return 1
    return 0


# ---------------------------------------------------------------------------
# active: authorization-gated live probe
# ---------------------------------------------------------------------------
def cmd_probe(args) -> int:
    allowlist = []
    if args.target_allowlist:
        allowlist = [h.strip() for h in args.target_allowlist.split(",") if h.strip()]
    # The banner prints to stderr so it is always visible even with --json.
    print(AUTHORIZED_USE_BANNER, file=sys.stderr)
    try:
        report = probe_target(
            args.target,
            authorized=args.authorized,
            allowlist=allowlist,
            rate_limit=args.rate_limit,
            param=args.param,
        )
    except (AuthorizationError, ScopeError) as exc:
        raise SystemExit(f"error: {exc}")
    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        print("Active probe (authorized)")
        print("=" * 60)
        print(f"  target        : {report.target}")
        print(f"  canaries sent : {report.sent}")
        print(f"  blocked       : {report.blocked_count}")
        print(f"  block rate    : {_fmt_pct(report.block_rate)}")
        print()
        print("Per canary")
        print("-" * 60)
        for r in report.results:
            mark = "BLOCKED" if r.blocked else "PASSED-THROUGH"
            extra = f" ({r.error})" if r.error else f" [HTTP {r.status}]"
            print(f"  {mark:<16} [{r.category}] {r.canary_id}{extra}")
    if args.fail_under is not None and report.block_rate < args.fail_under:
        return 1
    return 0


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

    p_evade = sub.add_parser(
        "evade",
        help="measure evasion-resistance under semantics-preserving mutation",
    )
    _add_detector_args(p_evade)
    p_evade.add_argument(
        "--only",
        metavar="IDS",
        help=(
            "comma-separated transform ids to restrict to (default: all). "
            "available: " + ", ".join(TRANSFORM_IDS)
        ),
    )
    p_evade.add_argument(
        "--fail-under",
        type=float,
        metavar="X",
        help="exit non-zero if evasion-resistance is below X (0..1)",
    )
    p_evade.add_argument("--json", action="store_true", help="emit JSON results")
    p_evade.set_defaults(func=cmd_evade)

    p_diag = sub.add_parser(
        "diagnose",
        help="attribute matches to rules; find dead/overbroad/redundant rules",
    )
    p_diag.add_argument(
        "--rules", metavar="FILE", help="path to a JSON regex ruleset (required)"
    )
    p_diag.add_argument(
        "--corpus", metavar="FILE", help="use a custom corpus JSON file"
    )
    p_diag.add_argument(
        "--fail-on-dead",
        action="store_true",
        help="exit non-zero if any rule matches nothing in the corpus",
    )
    p_diag.add_argument(
        "--fail-on-overbroad",
        action="store_true",
        help="exit non-zero if any rule flags a benign entry",
    )
    p_diag.add_argument("--json", action="store_true", help="emit JSON results")
    p_diag.set_defaults(func=cmd_diagnose)

    # ----- passive: scan provided input -----------------------------------
    p_scan = sub.add_parser(
        "scan",
        help="PASSIVE (offline): run a detector over provided input (file/HAR/JSON)",
    )
    p_scan.add_argument("--rules", metavar="FILE", help="path to a JSON regex ruleset")
    p_scan.add_argument(
        "--callable",
        metavar="SPEC",
        help="Python detector as 'module:function' or 'file.py:function'",
    )
    p_scan.add_argument(
        "--input",
        metavar="FILE",
        required=True,
        help="local input file to scan (lines / JSON array / HAR capture)",
    )
    p_scan.add_argument(
        "--input-format",
        choices=("lines", "json", "har"),
        help="force the input format (default: auto-detect)",
    )
    p_scan.add_argument(
        "--fail-on-flag",
        action="store_true",
        help="exit non-zero if any input is flagged (CI use)",
    )
    p_scan.add_argument("--json", action="store_true", help="emit JSON results")
    p_scan.set_defaults(func=cmd_scan)

    # ----- passive: vuln-DB enrichment ------------------------------------
    p_enrich = sub.add_parser(
        "enrich",
        help="PASSIVE (offline): annotate packages/SBOM with the bundled vuln DB",
    )
    p_enrich.add_argument(
        "--sbom", metavar="FILE", help="a CycloneDX or SPDX SBOM JSON file"
    )
    p_enrich.add_argument(
        "--package",
        metavar="NAME",
        action="append",
        help="a package name to look up (repeatable)",
    )
    p_enrich.add_argument(
        "--ecosystem",
        metavar="ECO",
        help="restrict lookups to an ecosystem (PyPI/npm/Go/Maven/...)",
    )
    p_enrich.add_argument(
        "--fail-on-vuln",
        action="store_true",
        help="exit non-zero if any package has a known vuln (CI use)",
    )
    p_enrich.add_argument("--json", action="store_true", help="emit JSON results")
    p_enrich.set_defaults(func=cmd_enrich)

    # ----- active: authorization-gated live probe -------------------------
    p_probe = sub.add_parser(
        "probe",
        help=(
            "ACTIVE (AUTHORIZED USE ONLY, off by default): smoke-test a CONSENTED "
            "target's live WAF with detection canaries"
        ),
    )
    p_probe.add_argument(
        "--target", metavar="URL", required=True, help="the target URL to probe"
    )
    p_probe.add_argument(
        "--authorized",
        action="store_true",
        help=(
            "REQUIRED acknowledgement that you own or are authorized to test the "
            "target; active mode refuses to run without it"
        ),
    )
    p_probe.add_argument(
        "--target-allowlist",
        metavar="HOSTS",
        help=(
            "REQUIRED comma-separated allowlist of hostnames in scope; a target "
            "host not in this list is refused"
        ),
    )
    p_probe.add_argument(
        "--rate-limit",
        type=float,
        default=1.0,
        metavar="RPS",
        help="max requests per second (must be > 0, default 1.0)",
    )
    p_probe.add_argument(
        "--param",
        default="q",
        metavar="NAME",
        help="query parameter to carry each canary (default 'q')",
    )
    p_probe.add_argument(
        "--fail-under",
        type=float,
        metavar="X",
        help="exit non-zero if the target's block rate is below X (0..1)",
    )
    p_probe.add_argument("--json", action="store_true", help="emit JSON results")
    p_probe.set_defaults(func=cmd_probe)

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
