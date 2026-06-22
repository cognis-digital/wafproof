"""Active mode: probe a CONSENTED target's live WAF — authorization-gated.

WARNING — AUTHORIZED USE ONLY.
==============================
This is the only part of wafproof that touches the network. It sends wafproof's
own benign, generic malicious-shaped canaries (the same strings in the built-in
corpus — ``<script>alert(1)</script>`` and the like) as a query parameter to a
URL **you operate or are explicitly authorized to test**, and records whether
the target's own defenses (a WAF, an input filter) blocked the request. It is a
way to verify *your own* perimeter actually catches what your rules say it
should — a defensive smoke test, not an attack tool.

It refuses to do anything unless ALL of these hold:

  * ``authorized=True`` — an explicit operator acknowledgement (the CLI
    ``--authorized`` flag). Default is OFF.
  * the target host is in an explicit ``allowlist`` (CLI ``--target-allowlist``).
    Any target whose host is not in scope is refused, loudly, before a single
    byte goes out.
  * a positive ``rate_limit`` (requests/second) is enforced between requests so
    a probe can never become a flood. Default is a conservative 1 req/s.

There are no exploit payloads here. The canaries are textbook-shape, length-
limited, single-shot strings designed to be *recognized and blocked*, not to
achieve code execution. wafproof never escalates, never chains, never persists.

Tests exercise this module against a localhost fixture server or a mock
transport ONLY — never a real external host.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlencode, urlsplit, urlunsplit

from .corpus import builtin_corpus

# A transport is: (method, url, headers) -> (status_code, body_text).
# The default transport uses urllib; tests inject a mock so nothing leaves the
# box. Keeping it injectable is what makes "active" testable offline.
Transport = Callable[[str, str, dict], "tuple[int, str]"]

DEFAULT_RATE_LIMIT = 1.0  # requests per second
MAX_CANARY_LEN = 256

AUTHORIZED_USE_BANNER = (
    "=" * 70 + "\n"
    "  wafproof ACTIVE PROBE — AUTHORIZED USE ONLY\n"
    "  You are sending detection canaries to a live target. Only proceed\n"
    "  against systems you own or are explicitly authorized to test.\n"
    "  Unauthorized probing may be illegal. This tool is defensive: it\n"
    "  verifies YOUR perimeter blocks what YOUR rules expect.\n"
    + "=" * 70
)


class AuthorizationError(RuntimeError):
    """Raised when active probing is attempted without satisfying the gate."""


class ScopeError(RuntimeError):
    """Raised when a target host is not in the allowlist."""


@dataclass
class ProbeResult:
    canary_id: str
    category: str
    text: str
    status: Optional[int]
    blocked: bool        # target appears to have blocked the canary (good)
    error: str = ""      # transport/error note, if any

    def as_dict(self) -> dict:
        return {
            "canary_id": self.canary_id,
            "category": self.category,
            "status": self.status,
            "blocked": self.blocked,
            "error": self.error,
        }


@dataclass
class ProbeReport:
    target: str
    results: list[ProbeResult] = field(default_factory=list)

    @property
    def sent(self) -> int:
        return len(self.results)

    @property
    def blocked_count(self) -> int:
        return sum(1 for r in self.results if r.blocked)

    @property
    def block_rate(self) -> float:
        return self.blocked_count / self.sent if self.sent else 0.0

    def as_dict(self) -> dict:
        return {
            "mode": "active",
            "target": self.target,
            "sent": self.sent,
            "blocked_count": self.blocked_count,
            "block_rate": round(self.block_rate, 6),
            "results": [r.as_dict() for r in self.results],
        }


def host_of(url: str) -> str:
    """Return the lowercase hostname of a URL (no port)."""
    return (urlsplit(url).hostname or "").lower()


def normalize_allowlist(allowlist) -> set[str]:
    return {str(h).strip().lower() for h in (allowlist or []) if str(h).strip()}


def check_authorization(
    target: str,
    *,
    authorized: bool,
    allowlist,
    rate_limit: float,
) -> None:
    """Enforce the full active-mode gate. Raises if any condition fails.

    This is deliberately separate from the probing loop so it can be unit-tested
    on its own and so the CLI can fail BEFORE constructing any transport.
    """
    if not authorized:
        raise AuthorizationError(
            "active probing is disabled by default; pass --authorized to confirm "
            "you are testing a system you own or are authorized to test"
        )
    scope = normalize_allowlist(allowlist)
    if not scope:
        raise AuthorizationError(
            "active probing requires a non-empty --target-allowlist (the hosts "
            "you are authorized to probe)"
        )
    if rate_limit <= 0:
        raise AuthorizationError("--rate-limit must be a positive requests/second value")
    h = host_of(target)
    if not h:
        raise ScopeError(f"target {target!r} has no resolvable host")
    if h not in scope:
        raise ScopeError(
            f"refusing to probe {h!r}: not in the authorized allowlist "
            f"{sorted(scope)}"
        )


def _looks_blocked(status: Optional[int], body: str) -> bool:
    """Heuristic: did the target block the canary?

    A WAF typically answers a blocked request with 403/406/501 or a short
    body containing a block notice. A 200 that reflects the canary back means it
    sailed through. This is intentionally conservative — it is a smoke test, and
    a false "not blocked" is the safe direction (it tells you to look closer).
    """
    if status is None:
        return False
    if status in (403, 406, 419, 429, 501):
        return True
    low = (body or "").lower()
    for marker in ("blocked", "forbidden", "access denied", "request rejected", "waf"):
        if marker in low:
            return True
    return False


def _build_probe_url(target: str, param: str, value: str) -> str:
    parts = urlsplit(target)
    query = urlencode({param: value})
    new_query = (parts.query + "&" + query) if parts.query else query
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def _urllib_transport(method: str, url: str, headers: dict) -> "tuple[int, str]":
    import urllib.request  # local import: never paid unless active mode runs

    req = urllib.request.Request(url, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 (scoped, gated)
            body = resp.read(4096).decode("utf-8", "replace")
            return resp.getcode(), body
    except urllib.error.HTTPError as exc:  # a 4xx/5xx is a normal, useful answer
        body = b""
        try:
            body = exc.read(4096)
        except Exception:  # pragma: no cover - defensive
            pass
        return exc.code, body.decode("utf-8", "replace")


def probe_target(
    target: str,
    *,
    authorized: bool = False,
    allowlist=None,
    rate_limit: float = DEFAULT_RATE_LIMIT,
    param: str = "q",
    canaries: Optional[list[dict]] = None,
    transport: Optional[Transport] = None,
    sleep: Optional[Callable[[float], None]] = None,
) -> ProbeReport:
    """Send detection canaries to a consented target and record block status.

    The full authorization gate (:func:`check_authorization`) is enforced first;
    nothing is sent if it fails. ``transport`` defaults to a urllib client but is
    injectable so tests run fully offline. ``sleep`` is injectable for the same
    reason; the real one enforces ``rate_limit``.
    """
    check_authorization(
        target, authorized=authorized, allowlist=allowlist, rate_limit=rate_limit
    )
    if transport is None:
        transport = _urllib_transport
    if sleep is None:
        import time

        sleep = time.sleep

    entries = canaries if canaries is not None else builtin_corpus()
    mal = [e for e in entries if e.get("label") == "malicious"]
    interval = 1.0 / rate_limit

    report = ProbeReport(target=target)
    headers = {"User-Agent": "wafproof-probe/1.0 (authorized defensive smoke test)"}
    for idx, e in enumerate(mal):
        value = str(e["text"])[:MAX_CANARY_LEN]
        url = _build_probe_url(target, param, value)
        status: Optional[int] = None
        err = ""
        blocked = False
        try:
            status, body = transport("GET", url, headers)
            blocked = _looks_blocked(status, body)
        except Exception as exc:  # network/transport problems are reported, not raised
            err = f"{type(exc).__name__}: {exc}"
        report.results.append(
            ProbeResult(
                canary_id=str(e.get("id", f"canary-{idx}")),
                category=str(e.get("category", "uncategorized")),
                text=value,
                status=status,
                blocked=blocked,
                error=err,
            )
        )
        if idx < len(mal) - 1:
            sleep(interval)
    return report
