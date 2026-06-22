"""Tests for offline vuln-DB enrichment.

These rely on the bundled cognis_vulndb.jsonl.gz. They use packages known to be
present (lodash/npm, rustc-serialize/crates.io) and a guaranteed-absent name.
All offline.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from wafproof.enrich import (
    EnrichmentReport,
    PackageVulns,
    enrich_packages,
    enrich_sbom_file,
    normalize_ecosystem,
    packages_from_sbom,
)
from wafproof.vulndb_local import VulnDB

FIXTURES = Path(__file__).parent / "fixtures"
ABSENT = "definitely-not-a-real-package-xyz"


@pytest.fixture(scope="module")
def db():
    return VulnDB()


def test_enrich_known_package_has_vulns(db):
    rep = enrich_packages(["lodash"], db=db)
    assert rep.packages[0].count > 0
    assert rep.total_vulns > 0


def test_enrich_absent_package_has_no_vulns(db):
    rep = enrich_packages([ABSENT], db=db)
    assert rep.packages[0].count == 0


def test_enrich_mixed_list(db):
    rep = enrich_packages(["lodash", ABSENT, "rustc-serialize"], db=db)
    assert len(rep.packages) == 3
    assert len(rep.vulnerable_packages) == 2


def test_enrich_dedupes_vuln_ids(db):
    rep = enrich_packages(["lodash"], db=db)
    ids = rep.packages[0].vuln_ids
    assert len(ids) == len(set(ids))


def test_enrich_records_max_severity(db):
    rep = enrich_packages(["lodash"], db=db)
    # lodash records carry CVSS vectors; max_severity should be non-empty
    assert rep.packages[0].max_severity != ""


def test_enrich_ecosystem_filter(db):
    # rustc-serialize is in crates.io; filtering to npm should drop it
    rep = enrich_packages(["rustc-serialize"], ecosystem="npm", db=db)
    assert rep.packages[0].count == 0


def test_enrich_ecosystem_filter_matches(db):
    rep = enrich_packages(["rustc-serialize"], ecosystem="crates.io", db=db)
    assert rep.packages[0].count > 0


def test_enrich_tuple_form(db):
    rep = enrich_packages([("lodash", "npm")], db=db)
    assert rep.packages[0].ecosystem == "npm"
    assert rep.packages[0].count > 0


def test_enrich_report_as_dict(db):
    rep = enrich_packages(["lodash", ABSENT], db=db)
    d = rep.as_dict()
    assert d["packages_checked"] == 2
    assert d["vulnerable_packages"] == 1
    assert d["total_vulns"] > 0
    assert len(d["results"]) == 2


def test_packagevulns_count():
    p = PackageVulns(package="x", ecosystem="npm", vuln_ids=["a", "b"])
    assert p.count == 2


def test_empty_enrichment_report():
    rep = EnrichmentReport()
    assert rep.total_vulns == 0
    assert rep.vulnerable_packages == []


# ----- SBOM parsing --------------------------------------------------------
def test_packages_from_cyclonedx():
    text = (FIXTURES / "sbom.cdx.json").read_text(encoding="utf-8")
    pairs = packages_from_sbom(text)
    names = {n for n, _ in pairs}
    assert "lodash" in names
    assert "rustc-serialize" in names
    # ecosystem extracted from purl
    ecos = dict(pairs)
    assert ecos["lodash"] == "npm"
    assert ecos["rustc-serialize"] == "cargo"


def test_packages_from_spdx():
    text = (FIXTURES / "sbom.spdx.json").read_text(encoding="utf-8")
    pairs = packages_from_sbom(text)
    names = {n for n, _ in pairs}
    assert "lodash" in names


def test_packages_from_sbom_invalid_json():
    with pytest.raises(ValueError, match="not valid JSON"):
        packages_from_sbom("{not json")


def test_packages_from_sbom_unrecognized():
    with pytest.raises(ValueError, match="unrecognized SBOM"):
        packages_from_sbom('{"foo": "bar"}')


def test_packages_from_sbom_non_object():
    with pytest.raises(ValueError, match="must be a JSON object"):
        packages_from_sbom("[1, 2, 3]")


def test_enrich_sbom_file(db):
    rep = enrich_sbom_file(str(FIXTURES / "sbom.cdx.json"), db=db)
    assert len(rep.packages) == 3
    assert len(rep.vulnerable_packages) >= 1


def test_enrich_sbom_file_missing(db):
    with pytest.raises(ValueError, match="not found"):
        enrich_sbom_file(str(FIXTURES / "nope.json"), db=db)


# ----- ecosystem normalization (purl token -> OSV label) -------------------
def test_normalize_ecosystem_known_tokens():
    assert normalize_ecosystem("cargo") == "crates.io"
    assert normalize_ecosystem("pypi") == "PyPI"
    assert normalize_ecosystem("golang") == "Go"
    assert normalize_ecosystem("npm") == "npm"


def test_normalize_ecosystem_passthrough():
    assert normalize_ecosystem("crates.io") == "crates.io"
    assert normalize_ecosystem("Weird") == "Weird"
    assert normalize_ecosystem("") == ""


def test_enrich_sbom_normalizes_cargo_to_crates_io(db):
    # rustc-serialize comes in as purl ecosystem 'cargo' but OSV labels it
    # 'crates.io'; normalization must bridge that so its vulns are found.
    rep = enrich_sbom_file(str(FIXTURES / "sbom.cdx.json"), db=db)
    rustc = [p for p in rep.packages if p.package == "rustc-serialize"][0]
    assert rustc.count > 0
