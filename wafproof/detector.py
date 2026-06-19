"""Detectors under test.

wafproof evaluates a *detector*: a function that, given a candidate string,
returns True if it considers the string malicious (a "hit"). Two kinds of
detector are supported:

  * A regex ruleset loaded from a JSON file. The detector flags a string if any
    rule's pattern matches.
  * A Python callable referenced as "package.module:function" (or a path to a
    .py file as "path/to/file.py:function"). The callable receives the string
    and must return a truthy value for malicious.

Loading and compiling a ruleset is deliberately strict so that a broken rule
fails loudly instead of silently never matching.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import re
from pathlib import Path
from typing import Callable

# A detector is just: str -> bool
Detector = Callable[[str], bool]


class RulesetError(ValueError):
    """Raised when a ruleset file is malformed or a pattern cannot compile."""


class Rule:
    """A single named regex rule."""

    __slots__ = ("id", "category", "pattern", "regex")

    def __init__(self, rid: str, category: str, pattern: str, flags: int):
        self.id = rid
        self.category = category
        self.pattern = pattern
        try:
            self.regex = re.compile(pattern, flags)
        except re.error as exc:  # pragma: no cover - exercised via load_ruleset
            raise RulesetError(f"rule {rid!r} has invalid regex: {exc}") from exc

    def matches(self, text: str) -> bool:
        return self.regex.search(text) is not None


def _parse_flags(value) -> int:
    """Translate a list of flag names (or a single name) into an re flag mask."""
    if value is None:
        return 0
    if isinstance(value, str):
        names = [value]
    elif isinstance(value, (list, tuple)):
        names = list(value)
    else:
        raise RulesetError(f"flags must be a string or list, got {type(value).__name__}")
    mapping = {
        "i": re.IGNORECASE,
        "ignorecase": re.IGNORECASE,
        "m": re.MULTILINE,
        "multiline": re.MULTILINE,
        "s": re.DOTALL,
        "dotall": re.DOTALL,
        "x": re.VERBOSE,
        "verbose": re.VERBOSE,
    }
    mask = 0
    for name in names:
        key = str(name).strip().lower()
        if key not in mapping:
            raise RulesetError(f"unknown regex flag: {name!r}")
        mask |= mapping[key]
    return mask


def load_ruleset(path: str | Path) -> list[Rule]:
    """Load and compile a regex ruleset from a JSON file.

    Expected shape::

        {
          "rules": [
            {"id": "x", "category": "xss", "pattern": "<script",
             "flags": ["i"]},
            ...
          ]
        }

    A bare top-level list of rule objects is also accepted.
    """
    p = Path(path)
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RulesetError(f"ruleset file not found: {p}") from exc
    except json.JSONDecodeError as exc:
        raise RulesetError(f"ruleset {p} is not valid JSON: {exc}") from exc

    if isinstance(raw, dict):
        rules_raw = raw.get("rules")
        if rules_raw is None:
            raise RulesetError("ruleset object must contain a 'rules' array")
    elif isinstance(raw, list):
        rules_raw = raw
    else:
        raise RulesetError("ruleset must be an object with 'rules' or a list")

    if not isinstance(rules_raw, list):
        raise RulesetError("'rules' must be an array")
    if not rules_raw:
        raise RulesetError("ruleset contains no rules")

    rules: list[Rule] = []
    seen: set[str] = set()
    for i, item in enumerate(rules_raw):
        if not isinstance(item, dict):
            raise RulesetError(f"rule #{i} is not an object")
        if "pattern" not in item:
            raise RulesetError(f"rule #{i} is missing 'pattern'")
        rid = str(item.get("id", f"rule-{i}"))
        if rid in seen:
            raise RulesetError(f"duplicate rule id: {rid!r}")
        seen.add(rid)
        category = str(item.get("category", "uncategorized"))
        flags = _parse_flags(item.get("flags"))
        rules.append(Rule(rid, category, str(item["pattern"]), flags))
    return rules


def ruleset_detector(rules: list[Rule]) -> Detector:
    """Build a detector that flags a string if ANY rule matches."""

    def detect(text: str) -> bool:
        return any(rule.matches(text) for rule in rules)

    return detect


def matching_rules(rules: list[Rule], text: str) -> list[Rule]:
    """Return the subset of rules that match a string (for explainability)."""
    return [rule for rule in rules if rule.matches(text)]


def load_callable(spec: str) -> Detector:
    """Load a Python callable detector from a "module:function" or
    "path/to/file.py:function" spec.
    """
    if ":" not in spec:
        raise ValueError(
            "callable spec must be 'module:function' or 'file.py:function'"
        )
    target, _, func_name = spec.rpartition(":")
    if not target or not func_name:
        raise ValueError("callable spec must include both a target and a function")

    if target.endswith(".py") or "/" in target or "\\" in target:
        file_path = Path(target)
        if not file_path.exists():
            raise ValueError(f"callable file not found: {file_path}")
        module_name = "_wafproof_detector_" + re.sub(r"\W+", "_", file_path.stem)
        spec_obj = importlib.util.spec_from_file_location(module_name, file_path)
        if spec_obj is None or spec_obj.loader is None:
            raise ValueError(f"could not import {file_path}")
        module = importlib.util.module_from_spec(spec_obj)
        spec_obj.loader.exec_module(module)
    else:
        module = importlib.import_module(target)

    try:
        func = getattr(module, func_name)
    except AttributeError as exc:
        raise ValueError(f"{target!r} has no attribute {func_name!r}") from exc
    if not callable(func):
        raise ValueError(f"{spec!r} is not callable")

    def detect(text: str) -> bool:
        return bool(func(text))

    return detect
