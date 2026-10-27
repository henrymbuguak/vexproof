"""Orchestrates the stages. This is the only module where stages meet.

Chapter 1 runs ingest and intel. Later chapters add symbols, evidence, prioritize and report.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from vexproof.domain import Finding, Package
from vexproof.ingest.direct import direct_dependency_names
from vexproof.ingest.sbom import load_sbom, packages_from_sbom
from vexproof.ingest.syft import generate_sbom
from vexproof.intel.disputes import find_disputes
from vexproof.intel.enrich import build_findings
from vexproof.intel.epss import load_epss
from vexproof.intel.http import JsonHttp
from vexproof.intel.kev import load_kev
from vexproof.intel.osv import OSVClient

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class IntelConfig:
    osv_url: str
    kev_url: str
    epss_url: str


@dataclass(frozen=True, slots=True)
class ScanResult:
    source: str
    commit: str | None
    packages: tuple[Package, ...]
    findings: tuple[Finding, ...]
    timings_s: Mapping[str, float] = field(default_factory=dict)


def collect_packages(
    repo: Path,
    sbom_path: Path | None,
    sbom_generator: Callable[[Path], dict[str, Any]] = generate_sbom,
) -> tuple[Package, ...]:
    document = load_sbom(sbom_path) if sbom_path else sbom_generator(repo)
    return packages_from_sbom(document, direct_dependency_names(repo))


def gather_intel(
    packages: Sequence[Package], http: JsonHttp, config: IntelConfig
) -> tuple[Finding, ...]:
    osv = OSVClient(http, config.osv_url)
    ids_by_package = osv.advisory_ids(packages)
    records = {pkg: [osv.record(i) for i in ids] for pkg, ids in ids_by_package.items() if ids}
    cves = {
        alias
        for recs in records.values()
        for rec in recs
        for alias in (str(rec["id"]), *(str(a) for a in rec.get("aliases") or []))
        if alias.startswith("CVE-")
    }
    kev = load_kev(http, config.kev_url)
    epss = load_epss(http, config.epss_url, cves)
    disputes = {pkg: find_disputes(pkg, recs, osv.record) for pkg, recs in records.items()}
    return build_findings(records, kev, epss, disputes)


def scan(
    repo: Path,
    *,
    http: JsonHttp,
    config: IntelConfig,
    sbom_path: Path | None = None,
    source: str | None = None,
    commit: str | None = None,
    sbom_generator: Callable[[Path], dict[str, Any]] = generate_sbom,
) -> ScanResult:
    timings: dict[str, float] = {}
    started = time.perf_counter()
    packages = collect_packages(repo, sbom_path, sbom_generator)
    timings["ingest"] = time.perf_counter() - started
    log.info("ingest_done", packages=len(packages), direct=sum(p.direct for p in packages))

    started = time.perf_counter()
    findings = gather_intel(packages, http, config)
    timings["intel"] = time.perf_counter() - started
    log.info("intel_done", findings=len(findings), kev=sum(f.signals.in_kev for f in findings))

    return ScanResult(
        source=source or str(repo),
        commit=commit,
        packages=packages,
        findings=findings,
        timings_s=timings,
    )
