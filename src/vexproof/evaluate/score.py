"""Scores a findings file against an observation of the running project."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from vexproof.domain import Finding, Level, Verdict
from vexproof.errors import IngestError
from vexproof.evidence.clear import relevant_modules
from vexproof.symbols.gold import GoldCase

# How the select stage records its outcome in a finding's notes (see pipeline.selection_counts).
_NONE_MATCH = "none of the changed functions"
_ASKED = (_NONE_MATCH, "rejected by verifier", "symbol selection")

ClearStatus = Literal["consistent", "falsified", "uncheckable"]
PathStatus = Literal["confirmed", "not_exercised"]


class Observation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    workload: str
    python: str
    packages: dict[str, str] = {}
    seconds: float = 0.0
    steps: tuple[dict[str, Any], ...] = ()
    loaded_modules: frozenset[str]
    executed_functions: frozenset[str]


class Closure(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    reached: frozenset[str]
    unreached: frozenset[str] = frozenset()
    blockers: tuple[str, ...] = ()


class ScanRecord(BaseModel):
    """The parts of `scan --json` output the evaluation reads."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    source: str = ""
    commit: str | None = None
    findings: tuple[Finding, ...]
    closure: Closure | None = None
    model: dict[str, Any] | None = None
    timings_s: dict[str, float] = {}


def load_record(data: Mapping[str, Any]) -> ScanRecord:
    try:
        return ScanRecord.model_validate(data)
    except ValidationError as exc:
        raise IngestError(f"not a findings file from `vexproof scan --json`: {exc}") from exc


def load_observation(data: Mapping[str, Any]) -> Observation:
    try:
        return Observation.model_validate(data)
    except ValidationError as exc:
        raise IngestError(f"not an observation file from eval/dynamic/observe.py: {exc}") from exc


@dataclass(frozen=True)
class ClosureCheck:
    """Every module that loaded at run time must be in the scan's closure."""

    loaded: int  # loaded modules the scan knows about
    missed: tuple[str, ...]  # loaded, known, but not in the closure: a soundness failure
    not_in_source: tuple[str, ...]  # loaded, but no Python source (compiled extensions)
    reached: int
    reached_not_loaded: int  # the closure's over-approximation under this workload


@dataclass(frozen=True)
class ClearCheck:
    finding: Finding
    modules: tuple[str, ...]
    status: ClearStatus
    loaded: tuple[str, ...] = ()


@dataclass(frozen=True)
class PathCheck:
    finding: Finding
    target: str
    status: PathStatus


@dataclass(frozen=True)
class GoldCheck:
    case: GoldCase
    picked: tuple[str, ...]
    correct: bool


@dataclass(frozen=True)
class Evaluation:
    record: ScanRecord
    observation: Observation
    closure: ClosureCheck | None
    clears: tuple[ClearCheck, ...]
    paths: tuple[PathCheck, ...]
    executed_open: tuple[Finding, ...]
    gold: tuple[GoldCheck, ...] = field(default=())

    @property
    def alerts(self) -> int:
        return len(self.record.findings)

    @property
    def open(self) -> int:
        return sum(1 for f in self.record.findings if f.verdict is None)

    @property
    def decided(self) -> int:
        return self.alerts - self.open

    @property
    def falsified(self) -> tuple[ClearCheck, ...]:
        return tuple(c for c in self.clears if c.status == "falsified")

    @property
    def confirmed(self) -> tuple[PathCheck, ...]:
        return tuple(p for p in self.paths if p.status == "confirmed")

    @property
    def sound(self) -> bool:
        """No clear contradicted by the run, and no loaded module missing from the closure."""
        missed = self.closure.missed if self.closure else ()
        return not self.falsified and not missed

    @property
    def cost_usd(self) -> float | None:
        """What a scan costs without recordings; older files only have this run's cost."""
        model = self.record.model or {}
        cost = model.get("fresh_cost_usd", model.get("cost_usd"))
        return float(cost) if isinstance(cost, int | float) else None

    @property
    def cost_is_fresh(self) -> bool:
        return "fresh_cost_usd" in (self.record.model or {})

    @property
    def scan_seconds(self) -> float:
        return sum(self.record.timings_s.values())


def evaluate(
    record: ScanRecord, observation: Observation, gold: Sequence[GoldCase] = ()
) -> Evaluation:
    return Evaluation(
        record=record,
        observation=observation,
        closure=_closure(record.closure, observation) if record.closure else None,
        clears=tuple(
            _clear(f, observation) for f in record.findings if f.verdict is Verdict.NOT_AFFECTED
        ),
        paths=tuple(
            _path(f, observation) for f in record.findings if f.verdict is Verdict.AFFECTED
        ),
        executed_open=tuple(
            f
            for f in record.findings
            if f.verdict is None
            and f.evidence is not None
            and any(s in observation.executed_functions for s in f.evidence.vulnerable_symbols)
        ),
        gold=tuple(_gold(gold, record.findings)),
    )


def _top(module: str) -> str:
    return module.split(".", 1)[0]


def _closure(closure: Closure, observation: Observation) -> ClosureCheck:
    known = closure.reached | closure.unreached
    scope = {_top(m) for m in known}
    loaded = {m for m in observation.loaded_modules if _top(m) in scope}
    return ClosureCheck(
        loaded=len(loaded & known),
        missed=tuple(sorted((loaded & known) - closure.reached)),
        not_in_source=tuple(sorted(loaded - known)),
        reached=len(closure.reached),
        reached_not_loaded=len(closure.reached - loaded),
    )


def _clear(finding: Finding, observation: Observation) -> ClearCheck:
    evidence = finding.evidence
    modules: set[str] | None = None
    if evidence is not None and evidence.level is not Level.L0_NOT_IMPORTED:
        modules = relevant_modules(finding, {c.qualname: c.module for c in evidence.candidates})
    if not modules:  # package-level clears are checked through the closure as a whole
        return ClearCheck(finding, (), "uncheckable")
    loaded = tuple(sorted(m for m in modules if m in observation.loaded_modules))
    return ClearCheck(
        finding, tuple(sorted(modules)), "falsified" if loaded else "consistent", loaded
    )


def _path(finding: Finding, observation: Observation) -> PathCheck:
    chain = finding.evidence.call_chain if finding.evidence else ()
    target = chain[-1].symbol if chain else ""
    status: PathStatus = (
        "confirmed" if target in observation.executed_functions else "not_exercised"
    )
    return PathCheck(finding, target, status)


def _gold(cases: Sequence[GoldCase], findings: Sequence[Finding]) -> list[GoldCheck]:
    by_advisory = {f.advisory.id: f for f in findings}
    checks = []
    for case in cases:
        finding = by_advisory.get(case.advisory)
        evidence = finding.evidence if finding else None
        notes = " ".join(evidence.notes) if evidence else ""
        if evidence is None or not (evidence.symbol_model or any(m in notes for m in _ASKED)):
            continue  # not in this scan, or the model was never asked
        picked = evidence.vulnerable_symbols
        if case.expected == "none":
            correct = _NONE_MATCH in notes
        else:
            chosen = set(picked)
            correct = (
                bool(chosen) and chosen <= set(case.expected) and set(case.must_include) <= chosen
            )
        checks.append(GoldCheck(case, picked, correct))
    return checks
