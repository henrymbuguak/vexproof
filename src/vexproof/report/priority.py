"""What to fix first, and why: an explainable ranking plus an upgrade plan per package.

Rules, in order:
- reachable (a verified call path) and any of: listed in CISA KEV, EPSS >= 10%, critical
  severity, or high severity in an internet-facing service whose criticality is not low
  -> fix now;
- reachable otherwise -> fix soon;
- open (no verified evidence either way) -> review, known-exploited first;
- cleared with evidence -> not affected.
Within a tier, alerts are ordered by a 0-100 score: severity (up to 50), EPSS (up to 30) and
KEV (20). The profile changes tiers and wording, never a verdict.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from packaging.version import InvalidVersion, Version

from vexproof.domain import Finding, Level, ServiceProfile, Verdict
from vexproof.report.context import short_symbol

EPSS_HIGH = 0.10
CRITICAL = 9.0
HIGH = 7.0
LABEL_SCORES = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 2.0}


class Tier(StrEnum):
    FIX_NOW = "fix now"
    FIX_SOON = "fix soon"
    REVIEW = "review"
    NOT_AFFECTED = "not affected"


TIER_ORDER = {tier: i for i, tier in enumerate(Tier)}


class Outcome(StrEnum):
    """How an alert was decided; the same split as the scan summary."""

    CLEARED_PACKAGE = "cleared_package"
    CLEARED_MODULE = "cleared_module"
    PATH_CERTAIN = "path_certain"
    PATH_REVIEWED = "path_reviewed"
    OPEN = "open"


@dataclass(frozen=True)
class Ranked:
    finding: Finding
    tier: Tier
    score: int
    outcome: Outcome
    reasons: tuple[str, ...]
    brief: str = ""

    @property
    def headline(self) -> str:
        return self.reasons[0]


@dataclass(frozen=True)
class Upgrade:
    """Upgrading one package to `target` resolves every alert in `resolves`.

    `reachable_target` is the smallest version that resolves every proven-reachable alert.
    """

    package: str
    installed: str
    target: str | None
    reachable_target: str | None
    tier: Tier
    resolves: tuple[str, ...]
    no_fix: tuple[str, ...]
    already_cleared: int

    @property
    def major_jump(self) -> bool:
        if self.target is None:
            return False
        try:
            return Version(self.target).major > Version(self.installed).major
        except InvalidVersion:
            return False


def outcome(finding: Finding) -> Outcome:
    evidence = finding.evidence
    if finding.verdict is Verdict.NOT_AFFECTED:
        if evidence is not None and evidence.level is Level.L0_NOT_IMPORTED:
            return Outcome.CLEARED_PACKAGE
        return Outcome.CLEARED_MODULE
    if finding.verdict is Verdict.AFFECTED:
        reviewed = evidence is not None and evidence.chain_model is not None
        return Outcome.PATH_REVIEWED if reviewed else Outcome.PATH_CERTAIN
    return Outcome.OPEN


def outcome_counts(findings: Sequence[Finding]) -> dict[Outcome, int]:
    counts = dict.fromkeys(Outcome, 0)
    for finding in findings:
        counts[outcome(finding)] += 1
    return counts


def severity(finding: Finding) -> float | None:
    """CVSS base score, or an estimate from the advisory's severity label."""
    if finding.signals.cvss is not None:
        return finding.signals.cvss
    label = (finding.advisory.severity_label or "").upper()
    return LABEL_SCORES.get(label)


def score(finding: Finding) -> int:
    sev = severity(finding)
    points = 5 * (sev if sev is not None else 5.0)
    points += 30 * (finding.signals.epss or 0.0)
    points += 20 if finding.signals.in_kev else 0
    return round(points)


def rank(findings: Sequence[Finding], profile: ServiceProfile | None = None) -> list[Ranked]:
    """Every finding with its tier, score and reasons, most urgent first."""
    ranked = [_rank_one(f, profile) for f in findings]
    return sorted(ranked, key=lambda r: (TIER_ORDER[r.tier], -r.score, r.finding.id))


def _rank_one(finding: Finding, profile: ServiceProfile | None) -> Ranked:
    how = outcome(finding)
    if how in {Outcome.CLEARED_PACKAGE, Outcome.CLEARED_MODULE}:
        reasons = _cleared_reasons(finding)
        return Ranked(finding, Tier.NOT_AFFECTED, score(finding), how, reasons, reasons[0])
    signals = _signal_reasons(finding)
    if how is Outcome.OPEN:
        reasons = (*_open_reasons(finding), *signals)
        return Ranked(finding, Tier.REVIEW, score(finding), how, reasons, "; ".join(reasons[:2]))
    urgent = _urgent(finding, profile)
    tier = Tier.FIX_NOW if urgent else Tier.FIX_SOON
    reasons = (_path_reason(finding), *urgent, *signals, *_fix_reason(finding))
    brief = "; ".join([_path_brief(finding), *(u.split(" in ")[0] for u in urgent[:1])])
    return Ranked(finding, tier, score(finding), how, tuple(dict.fromkeys(reasons)), brief)


def _urgent(finding: Finding, profile: ServiceProfile | None) -> list[str]:
    signals, sev = finding.signals, severity(finding)
    why = []
    if signals.in_kev:
        why.append("known exploited in the wild (CISA KEV)")
    if signals.epss is not None and signals.epss >= EPSS_HIGH:
        why.append(f"EPSS {signals.epss:.0%}: likely to see exploitation within 30 days")
    if sev is not None and sev >= CRITICAL:
        why.append("critical severity")
    elif (
        sev is not None
        and sev >= HIGH
        and profile is not None
        and profile.internet_facing
        and profile.criticality != "low"
    ):
        why.append(
            f"high severity in {profile.service}, an internet-facing "
            f"{profile.criticality}-criticality service"
        )
    return why


def _sev_text(finding: Finding) -> str:
    if finding.signals.cvss is not None:
        return f"CVSS {finding.signals.cvss:.1f}"
    return f"rated {(finding.advisory.severity_label or 'unknown').lower()}"


def _signal_reasons(finding: Finding) -> list[str]:
    signals = finding.signals
    parts = [_sev_text(finding)] if severity(finding) is not None else ["severity unknown"]
    if signals.epss is not None:
        parts.append(f"EPSS {signals.epss:.1%}")
    parts.append("in CISA KEV" if signals.in_kev else "not in CISA KEV")
    return [", ".join(parts)]


def _path_reason(finding: Finding) -> str:
    evidence = finding.evidence
    if evidence is None or not evidence.call_chain:  # pragma: no cover - affected implies a path
        return "reachable"
    chain = evidence.call_chain
    start, end = chain[0], chain[-1]
    hops = len(chain) - 1
    uncertain = sum(not h.certain for h in chain)
    how = (
        f"{uncertain} uncertain hop(s) reviewed by the model" if uncertain else "every hop certain"
    )
    return (
        f"reachable: {start.file}:{start.line} reaches {short_symbol(end.symbol)} "
        f"in {hops} hop(s), {how}"
    )


def _path_brief(finding: Finding) -> str:
    chain = finding.evidence.call_chain if finding.evidence else ()
    if not chain:  # pragma: no cover - affected implies a path
        return "reachable"
    uncertain = sum(not h.certain for h in chain)
    how = f"{uncertain} reviewed" if uncertain else "all certain"
    return (
        f"{chain[0].file}:{chain[0].line} -> {short_symbol(chain[-1].symbol)} "
        f"({len(chain) - 1} hops, {how})"
    )


def _fix_reason(finding: Finding) -> list[str]:
    fixed = finding.advisory.fixed_in
    name = finding.package.name
    return [f"fixed in {name} {fixed}"] if fixed else [f"no fixed version of {name} published"]


def _open_reasons(finding: Finding) -> list[str]:
    evidence, advisory = finding.evidence, finding.advisory
    reasons: list[str] = []
    if finding.signals.in_kev:
        reasons.append("known exploited in the wild (CISA KEV): review first")
    if evidence is None:
        reasons.append("not analysed (scan ran without analysis)")
    elif evidence.level is Level.L1_SYMBOL and evidence.vulnerable_symbols:
        names = ", ".join(short_symbol(s) for s in evidence.vulnerable_symbols[:2])
        reasons.append(f"vulnerable function {names} found; no verified call path from your code")
    elif evidence.level is Level.L1_SYMBOL and evidence.symbol_model:
        reasons.append("none of the functions the fix changed matches the advisory")
    elif evidence.level is Level.L1_SYMBOL:
        reasons.append("the fix's changed functions are known; not traced (no model)")
    elif evidence.level is Level.L2_MODULE:
        reasons.append("only the changed module is known, and it is not proven unused")
    else:
        reasons.append("no Python fix code to check against")
    if advisory.disputed_by:
        reasons.append(
            f"disputed: the reviewed record {advisory.disputed_by} says this version is not "
            "affected"
        )
    return reasons


def _cleared_reasons(finding: Finding) -> tuple[str, ...]:
    evidence = finding.evidence
    if evidence is None or evidence.level is Level.L0_NOT_IMPORTED:
        return ("package never imported by your code",)
    loaded = [n for n in evidence.notes if n.startswith("never loaded by your code")]
    if loaded:
        return (f"vulnerable module {loaded[-1]}",)
    return ("vulnerable module never loaded by your code",)


def upgrade_plan(ranked: Sequence[Ranked]) -> list[Upgrade]:
    """One upgrade per package with an alert still standing: the lowest version fixing them all."""
    groups: dict[tuple[str, str], list[Ranked]] = defaultdict(list)
    for item in ranked:
        package = item.finding.package
        groups[package.name, package.version].append(item)
    plans = [_upgrade(name, version, items) for (name, version), items in groups.items()]
    standing = [p for p in plans if p is not None]
    return sorted(standing, key=lambda u: (TIER_ORDER[u.tier], -len(u.resolves), u.package))


def _upgrade(name: str, installed: str, items: list[Ranked]) -> Upgrade | None:
    standing = [i for i in items if i.tier is not Tier.NOT_AFFECTED]
    if not standing:
        return None
    fixes: list[tuple[Version, str]] = []
    reachable: list[Version] = []
    no_fix: list[str] = []
    for item in standing:
        fixed = _version(item.finding.advisory.fixed_in)
        if fixed is None:
            no_fix.append(item.finding.advisory.id)
            continue
        fixes.append((fixed, item.finding.advisory.id))
        if item.tier in {Tier.FIX_NOW, Tier.FIX_SOON}:
            reachable.append(fixed)
    target = max(fixes)[0] if fixes else None
    cleared = [i for i in items if i.tier is Tier.NOT_AFFECTED]
    return Upgrade(
        package=name,
        installed=installed,
        target=str(target) if target else None,
        reachable_target=str(max(reachable)) if reachable else None,
        tier=min((i.tier for i in standing), key=TIER_ORDER.__getitem__),
        resolves=tuple(sorted(advisory for _, advisory in fixes)),
        no_fix=tuple(sorted(no_fix)),
        already_cleared=len(cleared),
    )


def _version(text: str | None) -> Version | None:
    if not text:
        return None
    try:
        return Version(text)
    except InvalidVersion:
        return None
