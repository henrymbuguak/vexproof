"""Findings in every state the report stage distinguishes, built directly (no scan needed)."""

from __future__ import annotations

from datetime import UTC, datetime

from vexproof.domain import (
    Advisory,
    Evidence,
    Finding,
    Hop,
    Level,
    Package,
    ServiceProfile,
    Signals,
    Verdict,
)
from vexproof.report.context import ReportContext

PILLOW = Package(name="Pillow", version="4.3.0")
DJANGO = Package(name="Django", version="2.0", purl="pkg:pypi/django@2.0")
SOURCE = "https://github.com/Acme/Shop.git"
COMMIT = "1aa90f67f4559a36d8049d8a2d3fe622791ee95c"
WHEN = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
PUBLIC = ServiceProfile(
    service="shop", internet_facing=True, handles_personal_data=True, criticality="high"
)
INTERNAL = ServiceProfile(
    service="batch", internet_facing=False, handles_personal_data=False, criticality="high"
)
HOSTILE = '<script>alert(1)</script> [bold]x[/bold] "quoted" & :cloud:'

CHAIN = (
    Hop(file="shop/admin.py", line=20, symbol="shop.admin", via="start"),
    Hop(file="PIL/Image.py", line=2549, symbol="PIL.Image.open"),
    Hop(file="PIL/IcoImagePlugin.py", line=153, symbol="PIL.IcoImagePlugin.IcoFile.frame"),
)


def _chain(reviewed: bool) -> tuple[Hop, ...]:
    if not reviewed:
        return CHAIN
    return (CHAIN[0], CHAIN[1].model_copy(update={"certain": False}), CHAIN[2])


def finding(
    advisory: str,
    *,
    package: Package = PILLOW,
    verdict: Verdict | None = None,
    level: Level = Level.L1_SYMBOL,
    cvss: float | None = 7.5,
    epss: float | None = 0.01,
    kev: bool = False,
    fixed_in: str | None = "8.1.2",
    reviewed: bool = False,
    picks: tuple[str, ...] = (),
    model: str | None = None,
    disputed_by: str | None = None,
    label: str | None = None,
    notes: tuple[str, ...] = (),
    summary: str = "",
) -> Finding:
    affected = verdict is Verdict.AFFECTED
    return Finding(
        id=f"{package.name}@{package.version}:{advisory}",
        package=package,
        advisory=Advisory(
            id=advisory,
            aliases=(f"CVE-{advisory}",),
            summary=summary or f"{advisory} summary",
            fixed_in=fixed_in,
            severity_label=label,
            disputed_by=disputed_by,
        ),
        signals=Signals(cvss=cvss, epss=epss, in_kev=kev),
        verdict=verdict,
        justification="vulnerable_code_not_in_execute_path"
        if verdict is Verdict.NOT_AFFECTED
        else None,
        evidence=Evidence(
            level=level,
            vulnerable_symbols=picks or ((CHAIN[-1].symbol,) if affected else ()),
            symbol_model=model or ("fake / symbol_pick.v1" if affected else None),
            call_chain=_chain(reviewed) if affected else (),
            chain_model="fake / trace_path.v3" if reviewed else None,
            fix_commits=("https://github.com/python-pillow/Pillow/commit/756fff3",),
            notes=notes,
        ),
    )


def context(*findings: Finding, profile: ServiceProfile | None = None) -> ReportContext:
    return ReportContext(
        source=SOURCE,
        commit=COMMIT,
        findings=findings,
        generated_at=WHEN,
        tooling="vexproof test",
        profile=profile,
    )


def mixed() -> tuple[Finding, ...]:
    """One finding per outcome, two packages."""
    return (
        finding("GHSA-kev", verdict=Verdict.AFFECTED, kev=True, fixed_in="9.0.0"),
        finding("GHSA-high", verdict=Verdict.AFFECTED, reviewed=True, fixed_in="8.1.2"),
        finding("GHSA-open", cvss=None, label="MODERATE", fixed_in="10.0.0"),
        finding(
            "GHSA-gone",
            verdict=Verdict.NOT_AFFECTED,
            notes=("never loaded by your code: PIL.GdImageFile (nothing loads it)",),
            fixed_in="11.0.0",
        ),
        finding("GHSA-dj", package=DJANGO, level=Level.L3_NONE, fixed_in=None),
        finding(
            "GHSA-dj0",
            package=DJANGO,
            verdict=Verdict.NOT_AFFECTED,
            level=Level.L0_NOT_IMPORTED,
            fixed_in="2.0.1",
        ),
    )
