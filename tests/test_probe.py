"""Tests for the active (authorization-gated) probe module.

Every test here uses an injected mock transport or a localhost fixture server.
NOTHING in this file contacts a real external host. The gate (authorized flag +
allowlist + positive rate-limit) is exercised exhaustively because it is the
safety boundary of the whole tool.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs

import pytest

from wafproof.probe import (
    DEFAULT_RATE_LIMIT,
    MAX_CANARY_LEN,
    AuthorizationError,
    ProbeReport,
    ScopeError,
    check_authorization,
    host_of,
    normalize_allowlist,
    probe_target,
)


# ---------------------------------------------------------------------------
# the authorization gate — the safety boundary
# ---------------------------------------------------------------------------
def test_gate_refuses_without_authorized():
    with pytest.raises(AuthorizationError, match="disabled by default"):
        check_authorization(
            "http://localhost/x", authorized=False, allowlist=["localhost"], rate_limit=1.0
        )


def test_gate_refuses_empty_allowlist():
    with pytest.raises(AuthorizationError, match="non-empty"):
        check_authorization(
            "http://localhost/x", authorized=True, allowlist=[], rate_limit=1.0
        )


def test_gate_refuses_none_allowlist():
    with pytest.raises(AuthorizationError, match="non-empty"):
        check_authorization(
            "http://localhost/x", authorized=True, allowlist=None, rate_limit=1.0
        )


def test_gate_refuses_zero_rate_limit():
    with pytest.raises(AuthorizationError, match="positive"):
        check_authorization(
            "http://localhost/x", authorized=True, allowlist=["localhost"], rate_limit=0
        )


def test_gate_refuses_negative_rate_limit():
    with pytest.raises(AuthorizationError, match="positive"):
        check_authorization(
            "http://localhost/x", authorized=True, allowlist=["localhost"], rate_limit=-5
        )


def test_gate_refuses_host_not_in_allowlist():
    with pytest.raises(ScopeError, match="not in the authorized allowlist"):
        check_authorization(
            "http://evil.example/x",
            authorized=True,
            allowlist=["localhost", "myapp.test"],
            rate_limit=1.0,
        )


def test_gate_refuses_url_without_host():
    with pytest.raises(ScopeError, match="no resolvable host"):
        check_authorization(
            "not-a-url", authorized=True, allowlist=["localhost"], rate_limit=1.0
        )


def test_gate_passes_when_all_satisfied():
    # should not raise
    check_authorization(
        "http://localhost:8080/x",
        authorized=True,
        allowlist=["localhost"],
        rate_limit=2.0,
    )


def test_gate_allowlist_is_case_insensitive():
    check_authorization(
        "http://MyApp.Test/x",
        authorized=True,
        allowlist=["myapp.test"],
        rate_limit=1.0,
    )


def test_probe_target_refuses_unauthorized_before_sending():
    sent = []

    def transport(method, url, headers):
        sent.append(url)
        return 200, "ok"

    with pytest.raises(AuthorizationError):
        probe_target(
            "http://localhost/x",
            authorized=False,
            allowlist=["localhost"],
            transport=transport,
        )
    assert sent == []  # nothing was sent


def test_probe_target_refuses_out_of_scope_before_sending():
    sent = []

    def transport(method, url, headers):
        sent.append(url)
        return 200, "ok"

    with pytest.raises(ScopeError):
        probe_target(
            "http://evil.example/x",
            authorized=True,
            allowlist=["localhost"],
            transport=transport,
        )
    assert sent == []


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def test_host_of():
    assert host_of("http://localhost:8080/a?b=c") == "localhost"
    assert host_of("https://EXAMPLE.com/") == "example.com"
    assert host_of("garbage") == ""


def test_normalize_allowlist():
    assert normalize_allowlist([" Localhost ", "EXAMPLE.com", ""]) == {
        "localhost",
        "example.com",
    }


def test_default_rate_limit_is_conservative():
    assert DEFAULT_RATE_LIMIT == 1.0


# ---------------------------------------------------------------------------
# probing behavior with a mock transport (offline)
# ---------------------------------------------------------------------------
def _blocking_transport(blocked_substrings):
    calls = []

    def transport(method, url, headers):
        calls.append((method, url, headers))
        low = url.lower()
        if any(s in low for s in blocked_substrings):
            return 403, "Forbidden by WAF"
        return 200, "ok"

    return transport, calls


def test_probe_sends_all_malicious_canaries():
    transport, calls = _blocking_transport([])
    rep = probe_target(
        "http://localhost/s",
        authorized=True,
        allowlist=["localhost"],
        rate_limit=1000,
        transport=transport,
        sleep=lambda s: None,
    )
    # built-in corpus has malicious canaries across 4 categories
    assert rep.sent == len(calls)
    assert rep.sent > 5


def test_probe_detects_blocked_canaries():
    transport, _ = _blocking_transport(["script", "union", "passwd"])
    rep = probe_target(
        "http://localhost/s",
        authorized=True,
        allowlist=["localhost"],
        rate_limit=1000,
        transport=transport,
        sleep=lambda s: None,
    )
    assert rep.blocked_count >= 1
    assert 0.0 <= rep.block_rate <= 1.0


def test_probe_all_blocked_yields_full_block_rate():
    # a transport that blocks everything
    def transport(method, url, headers):
        return 403, "blocked"

    rep = probe_target(
        "http://localhost/s",
        authorized=True,
        allowlist=["localhost"],
        rate_limit=1000,
        transport=transport,
        sleep=lambda s: None,
    )
    assert rep.block_rate == 1.0


def test_probe_none_blocked_yields_zero():
    def transport(method, url, headers):
        return 200, "reflected ok"

    rep = probe_target(
        "http://localhost/s",
        authorized=True,
        allowlist=["localhost"],
        rate_limit=1000,
        transport=transport,
        sleep=lambda s: None,
    )
    assert rep.block_rate == 0.0
    assert rep.blocked_count == 0


def test_probe_rate_limit_sleeps_between_requests():
    sleeps = []
    transport, _ = _blocking_transport([])
    probe_target(
        "http://localhost/s",
        authorized=True,
        allowlist=["localhost"],
        rate_limit=4.0,
        transport=transport,
        sleep=lambda s: sleeps.append(s),
    )
    # one sleep between each pair of canaries; interval = 1/rate
    assert sleeps
    assert all(abs(s - 0.25) < 1e-9 for s in sleeps)


def test_probe_transport_error_is_reported_not_raised():
    def transport(method, url, headers):
        raise ConnectionRefusedError("nope")

    rep = probe_target(
        "http://localhost/s",
        authorized=True,
        allowlist=["localhost"],
        rate_limit=1000,
        transport=transport,
        sleep=lambda s: None,
    )
    assert rep.sent > 0
    assert all(not r.blocked for r in rep.results)
    assert all(r.error for r in rep.results)


def test_probe_truncates_long_canary():
    long_text = "<script>" + "A" * 5000
    canaries = [{"id": "long", "category": "xss", "label": "malicious", "text": long_text}]
    captured = []

    def transport(method, url, headers):
        captured.append(url)
        return 200, "ok"

    probe_target(
        "http://localhost/s",
        authorized=True,
        allowlist=["localhost"],
        rate_limit=1000,
        canaries=canaries,
        transport=transport,
        sleep=lambda s: None,
    )
    # the encoded value in the URL derives from a value capped at MAX_CANARY_LEN
    assert captured
    # decoded length should not exceed the cap
    q = parse_qs(urlsplit(captured[0]).query)
    assert len(q["q"][0]) <= MAX_CANARY_LEN


def test_probe_custom_param_name():
    captured = []

    def transport(method, url, headers):
        captured.append(url)
        return 200, "ok"

    probe_target(
        "http://localhost/s",
        authorized=True,
        allowlist=["localhost"],
        rate_limit=1000,
        param="input",
        transport=transport,
        sleep=lambda s: None,
    )
    assert all("input=" in u for u in captured)


def test_probe_report_as_dict():
    transport, _ = _blocking_transport(["script"])
    rep = probe_target(
        "http://localhost/s",
        authorized=True,
        allowlist=["localhost"],
        rate_limit=1000,
        transport=transport,
        sleep=lambda s: None,
    )
    d = rep.as_dict()
    assert d["mode"] == "active"
    assert d["target"] == "http://localhost/s"
    assert "block_rate" in d
    assert isinstance(d["results"], list)


def test_probe_only_sends_malicious_entries():
    canaries = [
        {"id": "m", "category": "xss", "label": "malicious", "text": "<script>"},
        {"id": "b", "category": "xss", "label": "benign", "text": "hello"},
    ]
    captured = []

    def transport(method, url, headers):
        captured.append(url)
        return 200, "ok"

    rep = probe_target(
        "http://localhost/s",
        authorized=True,
        allowlist=["localhost"],
        rate_limit=1000,
        canaries=canaries,
        transport=transport,
        sleep=lambda s: None,
    )
    assert rep.sent == 1  # only the malicious one


def test_probe_report_empty_block_rate_is_zero():
    rep = ProbeReport(target="http://localhost/s")
    assert rep.block_rate == 0.0
    assert rep.sent == 0


# ---------------------------------------------------------------------------
# end-to-end against a LOCALHOST fixture server (still never external)
# ---------------------------------------------------------------------------
class _WAFHandler(BaseHTTPRequestHandler):
    """A toy WAF: blocks requests whose q value contains '<script' or 'union'."""

    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        q = parse_qs(urlsplit(self.path).query)
        value = (q.get("q") or [""])[0].lower()
        if "<script" in value or "union" in value:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Forbidden by WAF")
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")


@pytest.fixture
def local_waf_server():
    server = HTTPServer(("127.0.0.1", 0), _WAFHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://localhost:{port}/search"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_probe_against_localhost_fixture_server(local_waf_server):
    rep = probe_target(
        local_waf_server,
        authorized=True,
        allowlist=["localhost"],
        rate_limit=1000,
        sleep=lambda s: None,
    )
    assert rep.sent > 0
    # the toy WAF blocks script/union canaries, so at least one is blocked
    assert rep.blocked_count >= 1
    # and at least one (e.g. a path-traversal value) sails through with 200
    assert any(r.status == 200 for r in rep.results)
