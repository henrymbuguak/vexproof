"""Combine packages, OSV records, KEV and EPSS into raw findings (no verdicts yet)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from vexproof.domain import Finding, Package, Signals
from vexproof.intel.osv import to_advisory
from vexproof.intel.severity import base_score

_ID_PREFERENCE = ("GHSA-", "PYSEC-")


def _rank(advisory_id: str) -> int:
    for index, prefix in enumerate(_ID_PREFERENCE):
        if advisory_id.startswith(prefix):
            return index
    return len(_ID_PREFERENCE)


def dedupe_records(records: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """Drop withdrawn records and aliases of one another, keeping GHSA over PYSEC over others.

    Without this, one vulnerability published as both GHSA-x and PYSEC-y counts as two alerts.
    """
    kept: list[Mapping[str, Any]] = []
    seen: set[str] = set()
    for record in sorted(records, key=lambda r: (_rank(str(r["id"])), str(r["id"]))):
        if record.get("withdrawn"):
            continue
        names = {str(record["id"]), *(str(a) for a in record.get("aliases") or [])}
        if names & seen:
            continue
        seen |= names
        kept.append(record)
    return kept


def build_findings(
    package_records: Mapping[Package, Sequence[Mapping[str, Any]]],
    kev: frozenset[str],
    epss: Mapping[str, tuple[float, float]],
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for package in sorted(package_records, key=lambda p: (p.name, p.version)):
        for record in dedupe_records(package_records[package]):
            advisory = to_advisory(record, package)
            scored = [epss[c] for c in advisory.cve_ids if c in epss]
            best = max(scored, default=None)
            findings.append(
                Finding(
                    id=f"{advisory.id}:{package.name}@{package.version}",
                    package=package,
                    advisory=advisory,
                    signals=Signals(
                        cvss=base_score(advisory.cvss_vector),
                        epss=best[0] if best else None,
                        epss_percentile=best[1] if best else None,
                        in_kev=any(c in kev for c in advisory.cve_ids),
                    ),
                )
            )
    return tuple(findings)
