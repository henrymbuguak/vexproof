"""Combine packages, OSV records, KEV and EPSS into raw findings (no verdicts yet)."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from vexproof.domain import Advisory, Finding, Package, Signals
from vexproof.intel.osv import to_advisory
from vexproof.intel.severity import base_score

_ID_PREFERENCE = ("GHSA-", "PYSEC-")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")


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


def merge_unlinked_duplicates(advisories: Sequence[Advisory]) -> list[Advisory]:
    """Fold an alias-less advisory into the kept advisories it duplicates.

    Some records carry no aliases at all, so alias-based deduplication cannot link them:
    a PYSEC record describing CVE-2023-4863 only in prose, or a GHSA umbrella advisory for a
    release that fixed several CVEs which are also published individually.

    A record is merged only when (1) it has no aliases, (2) its text names at least one CVE id,
    and (3) every CVE it names is carried by other advisories with the same fixed version.
    It is then linked to all of those advisories. If it names a CVE that nothing else covers,
    it may describe something extra and is kept, so an alert is never hidden by a partial match.
    """
    merged: set[str] = set()
    extra: dict[str, list[str]] = {}
    for candidate in advisories:
        if candidate.aliases:
            continue
        mentioned = set(_CVE.findall(f"{candidate.summary} {candidate.details}"))
        if not mentioned:
            continue
        covering = [
            kept
            for kept in advisories
            if kept is not candidate
            and kept.id not in merged
            and kept.fixed_in == candidate.fixed_in
            and mentioned & set(kept.cve_ids)
        ]
        covered = {cve for kept in covering for cve in kept.cve_ids} & mentioned
        if covering and covered == mentioned:
            merged.add(candidate.id)
            for kept in covering:
                extra.setdefault(kept.id, []).append(candidate.id)
    return [
        a.model_copy(update={"aliases": (*a.aliases, *extra[a.id])}) if a.id in extra else a
        for a in advisories
        if a.id not in merged
    ]


def build_findings(
    package_records: Mapping[Package, Sequence[Mapping[str, Any]]],
    kev: frozenset[str],
    epss: Mapping[str, tuple[float, float]],
    disputes: Mapping[Package, Mapping[str, str]] | None = None,
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for package in sorted(package_records, key=lambda p: (p.name, p.version)):
        package_disputes = (disputes or {}).get(package, {})
        advisories = merge_unlinked_duplicates(
            [
                to_advisory(record, package).model_copy(
                    update={"disputed_by": package_disputes.get(str(record["id"]))}
                )
                for record in dedupe_records(package_records[package])
            ]
        )
        for advisory in advisories:
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
