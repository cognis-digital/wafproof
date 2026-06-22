"""Passive (offline) scanning of provided input against a detector.

This is wafproof's safe **default** mode. Where ``run``/``report`` measure a
detector against the *labeled canary corpus*, ``scan`` runs the same detector
over *input you provide* — request log lines, a saved HTTP capture, a field
dump, an SBOM — and reports which entries the detector flags, attributing each
flag to the rule(s) that fired.

Nothing here touches the network. ``scan`` only reads local files / stdin and
feeds the strings through a detector. It is the offline complement to the
authorization-gated active ``probe`` mode (see :mod:`wafproof.probe`).

Supported input shapes (auto-detected, or forced with ``--input-format``):

  * ``lines``  — one candidate string per line (e.g. access-log fields, a
    field dump). Blank lines and ``#`` comments are skipped.
  * ``json``   — a JSON array of strings, or an array of objects each carrying
    a ``text``/``value``/``input`` field (and optionally an ``id``).
  * ``har``    — a HAR 1.2 HTTP capture (``log.entries[].request``); the
    request URL, query values, and textual post body become candidates.

Each candidate becomes a :class:`ScanItem`. A scan produces a
:class:`ScanReport` with per-item flag status and matched-rule attribution, a
total flagged count, and (optionally) vuln-DB enrichment of any package names
mentioned, all of which serialize to JSON for pipelines.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit, parse_qsl

from .detector import Detector, Rule, matching_rules

INPUT_FORMATS = ("lines", "json", "har")


@dataclass
class ScanItem:
    """One candidate string lifted from the provided input."""

    id: str
    text: str
    source: str = ""  # provenance, e.g. "har:request-url" or "line:12"


@dataclass
class ScanFinding:
    """The outcome of running the detector over one ScanItem."""

    id: str
    text: str
    source: str
    flagged: bool
    matched_rules: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)


@dataclass
class ScanReport:
    findings: list[ScanFinding] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def flagged(self) -> list[ScanFinding]:
        return [f for f in self.findings if f.flagged]

    def as_dict(self) -> dict:
        return {
            "mode": "passive",
            "total": self.total,
            "flagged_count": len(self.flagged),
            "findings": [
                {
                    "id": f.id,
                    "text": f.text,
                    "source": f.source,
                    "flagged": f.flagged,
                    "matched_rules": list(f.matched_rules),
                    "categories": list(f.categories),
                }
                for f in self.findings
            ],
        }


# ---------------------------------------------------------------------------
# input loaders
# ---------------------------------------------------------------------------
def _items_from_lines(text: str) -> list[ScanItem]:
    items: list[ScanItem] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        items.append(ScanItem(id=f"line-{i}", text=raw, source=f"line:{i}"))
    return items


def _items_from_json(text: str) -> list[ScanItem]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"input is not valid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError("json input must be an array")
    items: list[ScanItem] = []
    for i, entry in enumerate(data):
        if isinstance(entry, str):
            items.append(ScanItem(id=f"json-{i}", text=entry, source=f"json:{i}"))
        elif isinstance(entry, dict):
            value = None
            for key in ("text", "value", "input", "payload"):
                if key in entry and isinstance(entry[key], str):
                    value = entry[key]
                    break
            if value is None:
                raise ValueError(
                    f"json input object #{i} has no text/value/input/payload string"
                )
            eid = str(entry.get("id", f"json-{i}"))
            items.append(ScanItem(id=eid, text=value, source=f"json:{i}"))
        else:
            raise ValueError(f"json input entry #{i} must be a string or object")
    return items


def _items_from_har(text: str) -> list[ScanItem]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"HAR input is not valid JSON: {exc}") from exc
    log = data.get("log") if isinstance(data, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise ValueError("HAR input must have log.entries[]")
    items: list[ScanItem] = []
    for i, entry in enumerate(entries):
        req = entry.get("request") if isinstance(entry, dict) else None
        if not isinstance(req, dict):
            continue
        url = req.get("url")
        if isinstance(url, str) and url:
            items.append(
                ScanItem(id=f"har-{i}-url", text=url, source="har:request-url")
            )
            # query values lifted out so a rule keying on a value, not the
            # whole URL, still gets a clean shot at each parameter.
            for k, v in parse_qsl(urlsplit(url).query):
                if v:
                    items.append(
                        ScanItem(
                            id=f"har-{i}-q-{k}",
                            text=v,
                            source=f"har:query:{k}",
                        )
                    )
        # textual post body
        post = req.get("postData")
        if isinstance(post, dict):
            body = post.get("text")
            if isinstance(body, str) and body:
                items.append(
                    ScanItem(id=f"har-{i}-body", text=body, source="har:post-body")
                )
    return items


def _detect_format(text: str) -> str:
    stripped = text.lstrip()
    if stripped.startswith("{"):
        # could be HAR or a JSON object; HAR has a log key
        try:
            data = json.loads(text)
            if isinstance(data, dict) and "log" in data:
                return "har"
        except json.JSONDecodeError:
            pass
        return "json"
    if stripped.startswith("["):
        return "json"
    return "lines"


def load_input(text: str, fmt: Optional[str] = None) -> list[ScanItem]:
    """Parse raw input text into ScanItems. ``fmt`` forces a format; otherwise
    it is auto-detected (json/har by leading brace/bracket, else lines).
    """
    chosen = fmt or _detect_format(text)
    if chosen not in INPUT_FORMATS:
        raise ValueError(
            f"unknown input format {chosen!r} (expected one of {INPUT_FORMATS})"
        )
    if chosen == "lines":
        return _items_from_lines(text)
    if chosen == "har":
        return _items_from_har(text)
    return _items_from_json(text)


def load_input_file(path: str | Path, fmt: Optional[str] = None) -> list[ScanItem]:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ValueError(f"input file not found: {p}") from exc
    return load_input(text, fmt)


# ---------------------------------------------------------------------------
# scanning
# ---------------------------------------------------------------------------
def scan_items(
    items: list[ScanItem],
    detector: Detector,
    rules: Optional[list[Rule]] = None,
) -> ScanReport:
    """Run ``detector`` over each item. If ``rules`` is supplied the matched
    rule ids/categories are attributed per item.
    """
    report = ScanReport()
    for item in items:
        flagged = bool(detector(item.text))
        matched: list[str] = []
        cats: list[str] = []
        if rules is not None and flagged:
            hits = matching_rules(rules, item.text)
            matched = [r.id for r in hits]
            cats = sorted({r.category for r in hits})
        report.findings.append(
            ScanFinding(
                id=item.id,
                text=item.text,
                source=item.source,
                flagged=flagged,
                matched_rules=matched,
                categories=cats,
            )
        )
    return report
