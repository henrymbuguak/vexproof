"""Orchestrates the stages. This is the only module where stages meet.

Stages: ingest -> intel -> analyze (Level 0 import closure, fix-commit shortlists)
-> select (Muse Spark picks the vulnerable function; a verifier checks it)
-> prove (module-level clears; call paths found by search, reviewed by Muse Spark, verified).
Reports (report/) and evaluation (evaluate/) read the result; they never change it.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from vexproof.domain import Evidence, Finding, Level, Package, Verdict
from vexproof.evidence.apply import PATH_REVIEWED, apply_trace
from vexproof.evidence.clear import MODULE_NOT_LOADED, clear_by_module
from vexproof.evidence.paths import registry_edges
from vexproof.evidence.trace import PROMPT_VERSION as TRACE_PROMPT
from vexproof.evidence.trace import Tracer
from vexproof.ingest.direct import direct_dependency_names
from vexproof.ingest.sbom import load_sbom, packages_from_sbom
from vexproof.ingest.syft import generate_sbom
from vexproof.intel.disputes import find_disputes
from vexproof.intel.enrich import build_findings
from vexproof.intel.epss import load_epss
from vexproof.intel.http import JsonHttp
from vexproof.intel.kev import load_kev
from vexproof.intel.osv import OSVClient
from vexproof.llm.factory import ModelStack
from vexproof.llm.types import BudgetExceededError, ModelError
from vexproof.sources.git import GitFixFetcher
from vexproof.sources.store import SourceStore
from vexproof.static.closure import reachability
from vexproof.static.codeindex import CodeIndex
from vexproof.static.levels import NOT_IN_EXECUTE_PATH, level0
from vexproof.static.modules import ModuleReach, module_reachability
from vexproof.static.project import scan_project
from vexproof.static.shortlist import FixSource, build_shortlist
from vexproof.symbols.apply import apply_outcome
from vexproof.symbols.select import pick_symbols
from vexproof.symbols.verify import Rejected, Verified, verify

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class IntelConfig:
    osv_url: str
    kev_url: str
    epss_url: str
    workers: int = 8


@dataclass(frozen=True, slots=True)
class Analyzers:
    """Collaborators for the analyze stage; tests pass fakes or local repositories."""

    store: SourceStore
    fetcher: GitFixFetcher | FixSource
    workers: int = 8


@dataclass(frozen=True, slots=True)
class ScanResult:
    source: str
    commit: str | None
    packages: tuple[Package, ...]
    findings: tuple[Finding, ...]
    timings_s: Mapping[str, float] = field(default_factory=dict)
    closure: ModuleClosure | None = None


@dataclass(frozen=True, slots=True)
class ModuleClosure:
    """Which modules the scan says your code can load; recorded so it can be checked later."""

    reached: tuple[str, ...]
    unreached: tuple[str, ...]
    blockers: tuple[str, ...]

    @classmethod
    def of(cls, reach: ModuleReach) -> ModuleClosure:
        return cls(
            reached=tuple(sorted(reach.reached)),
            unreached=tuple(sorted(set(reach.modules) - set(reach.reached))),
            blockers=tuple(reach.blockers),
        )


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
    unique_ids = sorted({i for ids in ids_by_package.values() for i in ids})
    with ThreadPoolExecutor(max_workers=config.workers) as pool:
        fetched = dict(zip(unique_ids, pool.map(osv.record, unique_ids), strict=True))
    records = {pkg: [fetched[i] for i in ids] for pkg, ids in ids_by_package.items() if ids}
    cves = {
        alias
        for recs in records.values()
        for rec in recs
        for alias in (str(rec["id"]), *(str(a) for a in rec.get("aliases") or []))
        if alias.startswith("CVE-")
    }
    kev = load_kev(http, config.kev_url)
    epss = load_epss(http, config.epss_url, cves)
    with ThreadPoolExecutor(max_workers=config.workers) as pool:
        dispute_maps = list(
            pool.map(lambda item: find_disputes(item[0], item[1], osv.record), records.items())
        )
    disputes = dict(zip(records, dispute_maps, strict=True))
    return build_findings(records, kev, epss, disputes)


def analyze(
    repo: Path,
    packages: Sequence[Package],
    findings: Sequence[Finding],
    analyzers: Analyzers,
) -> tuple[Finding, ...]:
    """Attach evidence to every finding: Level 0 clears, otherwise a fix-commit shortlist."""
    trees, failures = analyzers.store.get_many(packages, workers=analyzers.workers)
    reach = reachability(scan_project(repo), trees, failures)
    decisions = {f.package: level0(f.package, reach, trees, failures) for f in findings}
    pending = [f for f in findings if not decisions[f.package].cleared]
    if isinstance(analyzers.fetcher, GitFixFetcher):
        analyzers.fetcher.prefetch({c for f in pending for c in f.advisory.fix_commits})

    def evidence_for(finding: Finding) -> Finding:
        decision = decisions[finding.package]
        if decision.cleared:
            return finding.model_copy(
                update={
                    "verdict": Verdict.NOT_AFFECTED,
                    "justification": NOT_IN_EXECUTE_PATH,
                    "evidence": Evidence(
                        level=Level.L0_NOT_IMPORTED,
                        checks_passed=decision.checks,
                        notes=decision.notes,
                    ),
                }
            )
        tree = trees.get(finding.package)
        if tree is None:
            reason = failures.get(finding.package, "package source unavailable")
            evidence = Evidence(level=Level.L3_NONE, notes=(*decision.notes, reason))
            return finding.model_copy(update={"evidence": evidence})
        shortlist = build_shortlist(finding.advisory, tree, analyzers.fetcher)
        evidence = Evidence(
            level=shortlist.level,
            candidates=shortlist.candidates,
            changed_modules=shortlist.changed_modules,
            fix_commits=shortlist.fix_commits,
            native_changes=shortlist.native_changes,
            notes=(*decision.notes, *shortlist.notes),
        )
        return finding.model_copy(update={"evidence": evidence})

    with ThreadPoolExecutor(max_workers=analyzers.workers) as pool:
        return tuple(pool.map(evidence_for, findings))


def needs_selection(finding: Finding) -> bool:
    evidence = finding.evidence
    return bool(evidence and evidence.level is Level.L1_SYMBOL and evidence.candidates)


def select_symbols(
    findings: Sequence[Finding], stack: ModelStack, workers: int | None = None
) -> tuple[Finding, ...]:
    """Ask the model to pick the vulnerable function(s) for every L1 finding, then verify."""

    def one(finding: Finding) -> Finding:
        if not needs_selection(finding):
            return finding
        try:
            outcome: Verified | Rejected = verify(pick_symbols(finding, stack.caller), finding)
        except BudgetExceededError as exc:
            return _note(finding, f"symbol selection skipped: {exc}")
        except ModelError as exc:
            return _note(finding, f"symbol selection failed: {exc}")
        return apply_outcome(finding, outcome, f"{stack.label} / symbol_pick.v1")

    with ThreadPoolExecutor(max_workers=workers or stack.workers) as pool:
        return tuple(pool.map(one, findings))


def _note(finding: Finding, note: str) -> Finding:
    if finding.evidence is None:
        return finding
    evidence = finding.evidence.model_copy(update={"notes": (*finding.evidence.notes, note)})
    return finding.model_copy(update={"evidence": evidence})


def selection_counts(findings: Sequence[Finding]) -> dict[str, int]:
    counts = {"picked": 0, "none_match": 0, "rejected": 0, "failed": 0}
    for finding in findings:
        evidence = finding.evidence
        if evidence is None or evidence.level is not Level.L1_SYMBOL:
            continue
        notes = " ".join(evidence.notes)
        if evidence.vulnerable_symbols:
            counts["picked"] += 1
        elif "none of the changed functions" in notes:
            counts["none_match"] += 1
        elif "rejected by verifier" in notes:
            counts["rejected"] += 1
        elif "symbol selection" in notes:
            counts["failed"] += 1
    return counts


def level_counts(findings: Sequence[Finding]) -> dict[str, int]:
    counts = {level.value: 0 for level in Level}
    for finding in findings:
        if finding.evidence is not None:
            counts[finding.evidence.level.value] += 1
    return counts


def module_closure(repo: Path, packages: Sequence[Package], analyzers: Analyzers) -> ModuleReach:
    trees, failures = analyzers.store.get_many(packages, workers=analyzers.workers)
    return module_reachability(repo, trees, failures)


def prove(
    repo: Path,
    packages: Sequence[Package],
    findings: Sequence[Finding],
    analyzers: Analyzers,
    model: ModelStack | None = None,
    *,
    trace: bool = True,
    reach: ModuleReach | None = None,
) -> tuple[Finding, ...]:
    """Clear alerts whose vulnerable module is never loaded; find call paths to verified picks."""
    if reach is None:
        reach = module_closure(repo, packages, analyzers)
    cleared = tuple(clear_by_module(f, reach) for f in findings)
    if not trace or model is None:
        return cleared
    pending = [
        f for f in cleared if f.verdict is None and f.evidence and f.evidence.vulnerable_symbols
    ]
    if not pending:
        return cleared
    index = CodeIndex(reach)
    tracer = Tracer(index, registry_edges(index), model.caller)
    label = f"{model.label} / {TRACE_PROMPT}"
    budget_note: list[str] = []

    def one(finding: Finding) -> Finding:
        evidence = finding.evidence
        if finding.verdict is not None or evidence is None or not evidence.vulnerable_symbols:
            return finding
        if budget_note:
            return _note(finding, budget_note[0])
        for symbol in evidence.vulnerable_symbols[:3]:
            module = index.module_of(symbol)
            if module is None or not reach.is_reached(module):
                continue
            try:
                outcome = tracer.trace(symbol)
            except BudgetExceededError as exc:
                budget_note.append(f"call path search skipped: {exc}")
                return _note(finding, budget_note[0])
            finding = apply_trace(finding, symbol, outcome, label)
            if outcome.path is not None:
                break
        return finding

    # one at a time, in report order: a hop approved in one review is reused by later paths,
    # so the order must be fixed for runs (and their recordings) to be reproducible
    return tuple(one(f) for f in cleared)


def verdict_counts(findings: Sequence[Finding]) -> dict[str, int]:
    """How each alert stands: cleared (and how), proven reachable (and how), or open."""
    counts = {
        "cleared_package": 0,
        "cleared_module": 0,
        "path_certain": 0,
        "path_reviewed": 0,
        "open": 0,
    }
    for finding in findings:
        checks = finding.evidence.checks_passed if finding.evidence else ()
        if finding.verdict is Verdict.NOT_AFFECTED:
            counts["cleared_module" if MODULE_NOT_LOADED in checks else "cleared_package"] += 1
        elif finding.verdict is Verdict.AFFECTED:
            counts["path_reviewed" if PATH_REVIEWED in checks else "path_certain"] += 1
        else:
            counts["open"] += 1
    return counts


def scan(
    repo: Path,
    *,
    http: JsonHttp,
    config: IntelConfig,
    analyzers: Analyzers | None = None,
    model: ModelStack | None = None,
    sbom_path: Path | None = None,
    source: str | None = None,
    commit: str | None = None,
    sbom_generator: Callable[[Path], dict[str, Any]] = generate_sbom,
    trace: bool = True,
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

    if analyzers is not None and findings:
        started = time.perf_counter()
        findings = analyze(repo, packages, findings, analyzers)
        timings["analyze"] = time.perf_counter() - started
        log.info("analyze_done", **level_counts(findings))

    if model is not None and any(needs_selection(f) for f in findings):
        started = time.perf_counter()
        findings = select_symbols(findings, model)
        timings["select"] = time.perf_counter() - started
        log.info("select_done", **selection_counts(findings))

    closure: ModuleClosure | None = None
    if analyzers is not None and findings:
        started = time.perf_counter()
        reach = module_closure(repo, packages, analyzers)
        closure = ModuleClosure.of(reach)
        findings = prove(repo, packages, findings, analyzers, model, trace=trace, reach=reach)
        timings["prove"] = time.perf_counter() - started
        log.info("prove_done", **verdict_counts(findings))

    return ScanResult(
        source=source or str(repo),
        commit=commit,
        packages=packages,
        findings=findings,
        timings_s=timings,
        closure=closure,
    )
