"""End-to-end CLI tests for the scan / enrich / probe subcommands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wafproof.cli import main

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_RULES = ROOT / "examples" / "rules.json"
FIXTURES = Path(__file__).parent / "fixtures"
ABSENT = "definitely-not-a-real-package-xyz"


# ---------------------------------------------------------------------------
# scan (passive)
# ---------------------------------------------------------------------------
def test_scan_lines_text(capsys):
    rc = main(
        ["scan", "--rules", str(EXAMPLE_RULES), "--input", str(FIXTURES / "inputs.txt")]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Passive scan" in out
    assert "flagged" in out


def test_scan_json_output(capsys):
    rc = main(
        [
            "scan",
            "--rules",
            str(EXAMPLE_RULES),
            "--input",
            str(FIXTURES / "inputs.txt"),
            "--json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["mode"] == "passive"
    assert out["flagged_count"] >= 2


def test_scan_har(capsys):
    rc = main(
        [
            "scan",
            "--rules",
            str(EXAMPLE_RULES),
            "--input",
            str(FIXTURES / "capture.har"),
            "--json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    sources = {f["source"] for f in out["findings"]}
    assert any(s.startswith("har:") for s in sources)


def test_scan_fail_on_flag_exit_code(capsys):
    rc = main(
        [
            "scan",
            "--rules",
            str(EXAMPLE_RULES),
            "--input",
            str(FIXTURES / "inputs.txt"),
            "--fail-on-flag",
        ]
    )
    assert rc == 1  # malicious lines present


def test_scan_requires_detector():
    with pytest.raises(SystemExit, match="exactly one of"):
        main(["scan", "--input", str(FIXTURES / "inputs.txt")])


def test_scan_missing_input():
    with pytest.raises(SystemExit, match="not found"):
        main(["scan", "--rules", str(EXAMPLE_RULES), "--input", "no/such.txt"])


def test_scan_with_callable(capsys, tmp_path):
    det = tmp_path / "d.py"
    det.write_text("def f(s):\n    return '<script' in s.lower()\n", encoding="utf-8")
    rc = main(
        [
            "scan",
            "--callable",
            f"{det}:f",
            "--input",
            str(FIXTURES / "inputs.txt"),
            "--json",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["flagged_count"] == 1  # only the script line


# ---------------------------------------------------------------------------
# enrich (passive)
# ---------------------------------------------------------------------------
def test_enrich_package(capsys):
    rc = main(["enrich", "--package", "lodash", "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["total_vulns"] > 0


def test_enrich_sbom(capsys):
    rc = main(["enrich", "--sbom", str(FIXTURES / "sbom.cdx.json"), "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["packages_checked"] == 3


def test_enrich_text_output(capsys):
    rc = main(["enrich", "--package", "lodash"])
    assert rc == 0
    assert "vuln" in capsys.readouterr().out.lower()


def test_enrich_fail_on_vuln(capsys):
    rc = main(["enrich", "--package", "lodash", "--fail-on-vuln"])
    assert rc == 1


def test_enrich_fail_on_vuln_clean(capsys):
    rc = main(["enrich", "--package", ABSENT, "--fail-on-vuln"])
    assert rc == 0


def test_enrich_requires_one_source():
    with pytest.raises(SystemExit, match="exactly one"):
        main(["enrich"])


def test_enrich_rejects_both_sources():
    with pytest.raises(SystemExit, match="exactly one"):
        main(
            [
                "enrich",
                "--package",
                "lodash",
                "--sbom",
                str(FIXTURES / "sbom.cdx.json"),
            ]
        )


# ---------------------------------------------------------------------------
# probe (active, gated)
# ---------------------------------------------------------------------------
def test_probe_refuses_without_authorized(capsys):
    with pytest.raises(SystemExit, match="disabled by default"):
        main(["probe", "--target", "http://localhost/x", "--target-allowlist", "localhost"])


def test_probe_refuses_without_allowlist():
    with pytest.raises(SystemExit, match="non-empty"):
        main(["probe", "--target", "http://localhost/x", "--authorized"])


def test_probe_refuses_out_of_scope():
    with pytest.raises(SystemExit, match="not in the authorized allowlist"):
        main(
            [
                "probe",
                "--target",
                "http://evil.example/x",
                "--authorized",
                "--target-allowlist",
                "localhost",
            ]
        )


def test_probe_refuses_zero_rate():
    with pytest.raises(SystemExit, match="positive"):
        main(
            [
                "probe",
                "--target",
                "http://localhost/x",
                "--authorized",
                "--target-allowlist",
                "localhost",
                "--rate-limit",
                "0",
            ]
        )


def test_probe_prints_banner_to_stderr(capsys):
    with pytest.raises(SystemExit):
        main(["probe", "--target", "http://localhost/x", "--target-allowlist", "localhost"])
    err = capsys.readouterr().err
    assert "AUTHORIZED USE ONLY" in err
