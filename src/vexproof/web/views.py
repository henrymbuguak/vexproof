"""What each page shows, computed from a findings document. No HTML here."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vexproof.domain import Finding, Hop, ServiceProfile, Verdict
from vexproof.evaluate.markdown import summary_rows
from vexproof.evaluate.score import (
    Evaluation,
    ScanRecord,
    evaluate,
    load_observation,
    load_record,
)
from vexproof.report.context import ReportContext
from vexproof.report.priority import (
    Outcome,
    Ranked,
    Tier,
    Upgrade,
    outcome_counts,
    rank,
    upgrade_plan,
)
from vexproof.symbols.gold import GoldCase

_GITHUB = re.compile(r"^https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$")
TIER_CLASS = {
    Tier.FIX_NOW: "now",
    Tier.FIX_SOON: "soon",
    Tier.REVIEW: "review",
    Tier.NOT_AFFECTED: "clear",
}
SHOWN_OPEN = 12  # open alerts listed before "show the rest"
MIN_HERO_STEPS, MAX_HERO_STEPS = 3, 8  # long enough to show something, short enough to read


def repo_name(source: str) -> str:
    match = _GITHUB.match(source)
    return f"{match[1]}/{match[2]}" if match else (Path(source).name or source)


def finding_key(finding: Finding) -> str:
    """The URL segment for one alert: its advisory, plus the package when an id repeats."""
    return f"{finding.advisory.id}--{finding.package.name}"


@dataclass(frozen=True)
class Outcomes:
    total: int
    cleared: int
    reachable: int
    certain: int
    open: int

    def share(self, part: int) -> float:
        return 100 * part / self.total if self.total else 0.0


@dataclass(frozen=True)
class ResultView:
    record: ScanRecord
    profile: ServiceProfile | None
    ranked: list[Ranked]
    plans: list[Upgrade]
    outcomes: Outcomes
    evaluation: Evaluation | None

    @property
    def name(self) -> str:
        return repo_name(self.record.source)

    def tier(self, *tiers: Tier) -> list[Ranked]:
        return [r for r in self.ranked if r.tier in tiers]

    def find(self, key: str) -> Ranked | None:
        return next((r for r in self.ranked if finding_key(r.finding) == key), None)

    def context(self, tooling: str) -> ReportContext:
        return ReportContext(
            source=self.record.source,
            commit=self.record.commit,
            findings=self.record.findings,
            generated_at=datetime.now(UTC).replace(microsecond=0),
            tooling=tooling,
            profile=self.profile,
        )

    @property
    def evaluation_rows(self) -> list[tuple[str, str]]:
        return summary_rows(self.evaluation) if self.evaluation else []

    @property
    def headline_path(self) -> Ranked | None:
        """The best single example: the most urgent alert whose path is certain at every step,
        short enough to read, and confirmed by the run-time evaluation when there is one."""
        ran = {p.finding.id for p in self.evaluation.confirmed} if self.evaluation else None
        for item in self.tier(Tier.FIX_NOW, Tier.FIX_SOON):
            chain = _chain(item.finding)
            if (
                MIN_HERO_STEPS <= len(chain) <= MAX_HERO_STEPS
                and all(h.certain for h in chain)
                and (ran is None or item.finding.id in ran)
            ):
                return item
        return None


def _chain(finding: Finding) -> tuple[Hop, ...]:
    return finding.evidence.call_chain if finding.evidence else ()


def result_view(
    document: dict[str, Any],
    profile: ServiceProfile | None = None,
    observation: dict[str, Any] | None = None,
    gold: tuple[GoldCase, ...] = (),
) -> ResultView:
    record = load_record(document)
    ranked = rank(record.findings, profile)
    counts = outcome_counts(record.findings)
    outcomes = Outcomes(
        total=len(record.findings),
        cleared=counts[Outcome.CLEARED_PACKAGE] + counts[Outcome.CLEARED_MODULE],
        reachable=counts[Outcome.PATH_CERTAIN] + counts[Outcome.PATH_REVIEWED],
        certain=counts[Outcome.PATH_CERTAIN],
        open=counts[Outcome.OPEN],
    )
    evaluation = (
        evaluate(record, load_observation(observation), gold) if observation is not None else None
    )
    return ResultView(record, profile, ranked, upgrade_plan(ranked), outcomes, evaluation)


@dataclass(frozen=True)
class TraceStep:
    symbol: str
    where: str
    certain: bool
    first: bool
    last: bool
    label: str  # what this step is, when that is more than "called by the step above"


def trace(finding: Finding) -> list[TraceStep]:
    chain = _chain(finding)
    return [
        TraceStep(
            symbol=hop.symbol,
            where=f"{hop.file}:{hop.line}",
            certain=hop.certain,
            first=i == 0,
            last=i == len(chain) - 1,
            label=_label(hop, first=i == 0, last=i == len(chain) - 1),
        )
        for i, hop in enumerate(chain)
    ]


def _label(hop: Hop, *, first: bool, last: bool) -> str:
    rule = None if hop.via in _PLAIN else _VIA.get(hop.via, hop.via.replace("_", " "))
    if first:
        label = "Your code"
    elif last:
        label = "Vulnerable function" + (f", reached through {rule}" if rule else "")
    else:
        label = f"Through {rule}" if rule else ""
    if not hop.certain:
        uncertain = "uncertain step, judged plausible by the model"
        label = f"{label}: {uncertain}" if label else uncertain.capitalize()
    return label


_PLAIN = {"start", "call", "attr", "name"}
_VIA = {
    "string": "a dotted name in a string",
    "django_admin_upload": "Django admin upload validation",
    "django_admin_login": "Django admin login form",
    "django_view_dispatch": "Django view dispatch",
    "pillow_open_registry": "Pillow's format registry",
    "pillow_save_registry": "Pillow's save registry",
}


def verdict_sentence(item: Ranked) -> str:
    finding = item.finding
    if finding.verdict is Verdict.AFFECTED:
        return "Reachable: a verified call path runs from your code to the vulnerable function."
    if finding.verdict is Verdict.NOT_AFFECTED:
        return "Not affected: the vulnerable code is never loaded by your code."
    return "Open: there is no verified evidence either way yet."
