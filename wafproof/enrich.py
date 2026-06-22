"""Offline vuln-DB enrichment for scans and SBOMs.

wafproof ships a bundled, offline vulnerability corpus (``cognis_vulndb.jsonl.gz``,
~262k real OSV records across PyPI/npm/Go/Maven/RubyGems/crates.io/NuGet, see
:mod:`wafproof.vulndb_local`). This module wires that DB into the passive path so
a scan of an SBOM — or any list of package names — can be annotated with the
known vulnerabilities affecting those packages, entirely offline.

Two entry points:

  * :func:`enrich_packages` — given package names (optionally scoped to an
    ecosystem), return the matching DB records, summarized.
  * :func:`packages_from_sbom` — pull package names out of a CycloneDX or SPDX
    SBOM JSON so ``enrich_packages`` can act on them.

No network. The DB is loaded lazily and only when enrichment is requested, so
the common passive scan pays nothing for it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .vulndb_local import VulnDB


@dataclass
class PackageVulns:
    package: str
    ecosystem: str
    vuln_ids: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    max_severity: str = ""

    @property
    def count(self) -> int:
        return len(self.vuln_ids)

    def as_dict(self) -> dict:
        return {
            "package": self.package,
            "ecosystem": self.ecosystem,
            "vuln_count": self.count,
            "vuln_ids": list(self.vuln_ids),
            "aliases": list(self.aliases),
            "max_severity": self.max_severity,
        }


@dataclass
class EnrichmentReport:
    packages: list[PackageVulns] = field(default_factory=list)

    @property
    def total_vulns(self) -> int:
        return sum(p.count for p in self.packages)

    @property
    def vulnerable_packages(self) -> list[PackageVulns]:
        return [p for p in self.packages if p.count]

    def as_dict(self) -> dict:
        return {
            "packages_checked": len(self.packages),
            "vulnerable_packages": len(self.vulnerable_packages),
            "total_vulns": self.total_vulns,
            "results": [p.as_dict() for p in self.packages],
        }


# purl ecosystem tokens (pkg:<token>/...) -> the ecosystem label OSV uses in the
# bundled DB. Anything not listed is passed through unchanged.
_PURL_TO_OSV = {
    "cargo": "crates.io",
    "golang": "Go",
    "maven": "Maven",
    "npm": "npm",
    "pypi": "PyPI",
    "gem": "RubyGems",
    "nuget": "NuGet",
}


def normalize_ecosystem(eco: str) -> str:
    """Map a purl ecosystem token to the label used in the bundled OSV DB."""
    if not eco:
        return ""
    return _PURL_TO_OSV.get(eco.lower(), eco)


def _severity_rank(sev: str) -> int:
    """Rank a severity for "worst-of" selection.

    OSV severity is sometimes a label (LOW/HIGH/...) and sometimes a CVSS vector
    string. Labels rank on their ordinal; any non-empty value (e.g. a CVSS
    vector) ranks above "no severity recorded" so it is preferred over an empty
    string.
    """
    s = (sev or "").strip()
    if not s:
        return 0
    order = {"LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return order.get(s.upper(), 1)


def enrich_packages(
    packages,
    *,
    ecosystem: Optional[str] = None,
    db: Optional[VulnDB] = None,
) -> EnrichmentReport:
    """Annotate each package name with the vulns affecting it from the bundled DB.

    ``packages`` may be a list of names, or a list of ``(name, ecosystem)``
    tuples. ``ecosystem`` (if given) further filters every lookup.
    """
    db = db or VulnDB()
    report = EnrichmentReport()
    for entry in packages:
        if isinstance(entry, (tuple, list)) and len(entry) == 2:
            name, eco = str(entry[0]), str(entry[1])
        else:
            name, eco = str(entry), ecosystem or ""
        lookup_eco = normalize_ecosystem(ecosystem or eco) or None
        records = db.by_package(name, ecosystem=lookup_eco)
        ids: list[str] = []
        aliases: list[str] = []
        max_sev = ""
        for r in records:
            if r.get("id"):
                ids.append(r["id"])
            for a in (r.get("aliases") or []):
                aliases.append(a)
            sev = r.get("severity", "") or ""
            if _severity_rank(sev) > _severity_rank(max_sev):
                max_sev = sev
        report.packages.append(
            PackageVulns(
                package=name,
                ecosystem=eco or (ecosystem or ""),
                vuln_ids=sorted(set(ids)),
                aliases=sorted(set(aliases)),
                max_severity=max_sev,
            )
        )
    return report


def packages_from_sbom(text: str):
    """Extract ``(name, ecosystem)`` pairs from a CycloneDX or SPDX SBOM JSON.

    Returns a list of ``(name, ecosystem)`` tuples (ecosystem may be ""). Raises
    ValueError if the text is not an SBOM we recognize.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"SBOM is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("SBOM must be a JSON object")

    pairs: list[tuple[str, str]] = []
    # CycloneDX: top-level "components": [{ "name": ..., "purl": "pkg:pypi/..." }]
    if "components" in data and isinstance(data["components"], list):
        for c in data["components"]:
            if not isinstance(c, dict):
                continue
            name = c.get("name")
            if not name:
                continue
            eco = ""
            purl = c.get("purl", "")
            if isinstance(purl, str) and purl.startswith("pkg:"):
                eco = purl[len("pkg:"):].split("/", 1)[0]
            pairs.append((str(name), eco))
        return pairs
    # SPDX: "packages": [{ "name": ... }]
    if "packages" in data and isinstance(data["packages"], list):
        for p in data["packages"]:
            if isinstance(p, dict) and p.get("name"):
                pairs.append((str(p["name"]), ""))
        return pairs
    raise ValueError("unrecognized SBOM: expected CycloneDX 'components' or SPDX 'packages'")


def enrich_sbom_file(path: str | Path, *, db: Optional[VulnDB] = None) -> EnrichmentReport:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ValueError(f"SBOM file not found: {p}") from exc
    pairs = packages_from_sbom(text)
    return enrich_packages(pairs, db=db)
