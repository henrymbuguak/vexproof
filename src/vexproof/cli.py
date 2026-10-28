"""Command-line interface."""

from __future__ import annotations

import functools
import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from vexproof import __version__
from vexproof.config import Settings
from vexproof.domain import Finding, Level, ServiceProfile, Verdict
from vexproof.domain.profile import load_service_profile
from vexproof.errors import VexproofError
from vexproof.ingest.repo import checkout
from vexproof.intel.cache import Cache
from vexproof.intel.http import JsonHttp, make_client
from vexproof.logging import configure_logging
from vexproof.pipeline import Analyzers, IntelConfig, ScanResult, level_counts, scan
from vexproof.sources.git import GitFixFetcher
from vexproof.sources.pypi import PyPIClient
from vexproof.sources.store import SourceStore

app = typer.Typer(help="Which dependency vulnerabilities actually reach your code, with proof.")
console = Console()

LEVEL_LABELS = {
    Level.L0_NOT_IMPORTED.value: "not imported by your code (cleared)",
    Level.L1_SYMBOL.value: "changed functions found: check if your code calls them",
    Level.L2_MODULE.value: "only the changed module is known",
    Level.L3_NONE.value: "needs review: no usable Python fix code",
}


def _sort_key(finding: Finding) -> tuple[str, bool, float, float, str]:
    s = finding.signals
    level = finding.evidence.level.value if finding.evidence else "L9"
    return (level, not s.in_kev, -(s.epss or 0.0), -(s.cvss or 0.0), finding.id)


def _note(finding: Finding) -> str:
    if finding.evidence and finding.evidence.candidates:
        first = finding.evidence.candidates[0].qualname
        more = len(finding.evidence.candidates) - 1
        return first + (f" (+{more})" if more else "")
    if finding.advisory.disputed_by:
        return f"disputed by {finding.advisory.disputed_by}"
    if finding.evidence and finding.evidence.notes:
        return finding.evidence.notes[-1][:60]
    return ""


def _render(result: ScanResult, profile: ServiceProfile | None) -> None:
    table = Table(title=f"Findings for {result.source}", show_lines=False)
    for column in ("Level", "Package", "Advisory", "Fixed in", "CVSS", "EPSS", "KEV", "Evidence"):
        table.add_column(column, overflow="fold")
    for f in sorted(result.findings, key=_sort_key):
        table.add_row(
            f.evidence.level.value if f.evidence else "-",
            f"{f.package.name} {f.package.version}",
            f.advisory.id,
            f.advisory.fixed_in or "-",
            f"{f.signals.cvss:.1f}"
            if f.signals.cvss is not None
            else (f.advisory.severity_label or "-"),
            f"{f.signals.epss:.3f}" if f.signals.epss is not None else "-",
            "yes" if f.signals.in_kev else "",
            _note(f),
        )
    console.print(table)
    disputed = sum(1 for f in result.findings if f.advisory.disputed_by)
    if disputed:
        console.print(
            f"{disputed} alert(s) disputed: the reviewed GHSA record for the same CVE "
            "says this version is not affected"
        )
    affected = len({f.package for f in result.findings})
    console.print(
        f"{len(result.packages)} packages, {affected} with advisories, "
        f"[bold]{len(result.findings)} scanner alerts[/bold]"
        + (f" | profile: {profile.service}" if profile else "")
    )
    if result.findings and any(f.evidence for f in result.findings):
        _render_funnel(result.findings)


def _render_funnel(findings: tuple[Finding, ...]) -> None:
    counts = level_counts(findings)
    funnel = Table(title=f"Evidence levels for {len(findings)} alerts", show_header=False)
    funnel.add_column("Level")
    funnel.add_column("Meaning")
    funnel.add_column("Alerts", justify="right")
    for level, count in counts.items():
        funnel.add_row(level, LEVEL_LABELS[level], str(count))
    console.print(funnel)
    cleared = sum(1 for f in findings if f.verdict is Verdict.NOT_AFFECTED)
    console.print(
        f"Alert noise reduction so far: [bold]{100 * cleared / len(findings):.1f}%[/bold] "
        f"({cleared} of {len(findings)} cleared). Function-level checks come next."
    )


def _payload(result: ScanResult) -> dict[str, object]:
    return {
        "source": result.source,
        "commit": result.commit,
        "summary": {
            "alerts": len(result.findings),
            "levels": level_counts(result.findings),
            "cleared": sum(1 for f in result.findings if f.verdict is Verdict.NOT_AFFECTED),
        },
        "packages": [p.model_dump(mode="json") for p in result.packages],
        "findings": [f.model_dump(mode="json") for f in result.findings],
    }


@app.command("scan")
def scan_command(
    target: Annotated[
        str, typer.Argument(help="Local directory or https://github.com/<owner>/<repo>")
    ],
    commit: Annotated[
        str | None, typer.Option(help="Commit SHA (required for a GitHub URL)")
    ] = None,
    sbom: Annotated[
        Path | None, typer.Option(help="Use this CycloneDX/SPDX JSON instead of Syft")
    ] = None,
    profile: Annotated[Path | None, typer.Option(help="Service profile YAML")] = None,
    json_out: Annotated[
        Path | None, typer.Option("--json", help="Write findings JSON here")
    ] = None,
    analysis: Annotated[
        bool, typer.Option(help="Analyse imports and fix commits (off: intel only)")
    ] = True,
    workspace: Annotated[Path, typer.Option(help="Where GitHub repos are cloned")] = Path(
        ".vexproof-cache/repos"
    ),
    log_json: Annotated[bool, typer.Option(help="Emit JSON log lines")] = False,
) -> None:
    """Scan a repository: raw alerts, then the evidence level of each one."""
    configure_logging(json_output=log_json)
    settings = Settings()
    try:
        service_profile = load_service_profile(profile) if profile else None
        resolved_commit: str | None = commit
        if target.startswith("https://"):
            if not commit:
                raise typer.BadParameter("--commit is required when scanning a GitHub URL")
            repo = checkout(target, commit, workspace)
            repo_path, resolved_commit = repo.path, repo.commit
        else:
            repo_path = Path(target).resolve()
            if not repo_path.is_dir():
                raise typer.BadParameter(f"{target} is not a directory")
        cache = Cache(settings.cache_dir / "http.sqlite3")
        try:
            with make_client(settings.user_agent, settings.http_timeout_s) as client:
                http = JsonHttp(client, cache)
                analyzers = (
                    Analyzers(
                        store=SourceStore(
                            settings.cache_dir,
                            PyPIClient(
                                http, client, settings.pypi_url, settings.max_download_mb * 10**6
                            ),
                        ),
                        fetcher=GitFixFetcher(settings.cache_dir),
                        workers=settings.workers,
                    )
                    if analysis
                    else None
                )
                result = scan(
                    repo_path,
                    http=http,
                    config=IntelConfig(
                        settings.osv_url, settings.kev_url, settings.epss_url, settings.workers
                    ),
                    analyzers=analyzers,
                    sbom_path=sbom,
                    source=target,
                    commit=resolved_commit,
                )
        finally:
            cache.close()
    except VexproofError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    _render(result, service_profile)
    if json_out:
        json_out.write_text(json.dumps(_payload(result), indent=2) + "\n", encoding="utf-8")
        console.print(f"wrote {json_out}")


@app.command("show")
def show_command(
    findings_json: Annotated[Path, typer.Argument(help="JSON written by `vexproof scan --json`")],
    advisory: Annotated[str, typer.Argument(help="Advisory id, alias (CVE-...) or finding id")],
) -> None:
    """Explain one alert: its evidence level, candidate functions, fix commits and notes."""
    try:
        data = json.loads(findings_json.read_text(encoding="utf-8"))
        findings = [Finding.model_validate(f) for f in data["findings"]]
    except (OSError, ValueError, KeyError) as exc:
        console.print(f"[red]error:[/red] cannot read {findings_json}: {exc}")
        raise typer.Exit(code=2) from exc
    wanted = advisory.upper()
    matches = [
        f
        for f in findings
        if f.id.upper() == wanted
        or f.advisory.id.upper() == wanted
        or wanted in (a.upper() for a in f.advisory.aliases)
    ]
    if not matches:
        console.print(f"[red]no finding matches {advisory}[/red]")
        raise typer.Exit(code=1)
    for finding in matches:
        _show(finding)


def _show(f: Finding) -> None:
    """Print one finding; long lines (URLs, qualnames) soft-wrap so they stay copyable."""
    say = functools.partial(console.print, soft_wrap=True)
    adv, ev = f.advisory, f.evidence
    console.rule(f"{adv.id} in {f.package.name} {f.package.version}")
    say(f"[bold]{adv.summary or '(no summary)'}[/bold]")
    aliases = ", ".join(adv.aliases) or "-"
    say(f"aliases: {aliases} | fixed in: {adv.fixed_in or '-'}")
    signals = f.signals
    say(
        f"CVSS {signals.cvss if signals.cvss is not None else '-'} | "
        f"EPSS {signals.epss if signals.epss is not None else '-'} | "
        f"KEV {'yes' if signals.in_kev else 'no'}"
        + (f" | disputed by {adv.disputed_by}" if adv.disputed_by else "")
    )
    if ev is None:
        say("no evidence yet (scan was run with --no-analysis)")
        return
    verdict = f.verdict.value if f.verdict else "pending"
    say(f"evidence level: [bold]{ev.level.value}[/bold] ({LEVEL_LABELS[ev.level.value]})")
    say(f"verdict: {verdict}" + (f" ({f.justification})" if f.justification else ""))
    for candidate in ev.candidates:
        commits = ", ".join(candidate.commits)
        say(
            f"  candidate: {candidate.qualname}  [dim]{candidate.file}, "
            f"{candidate.changed_lines} changed line(s), commits {commits}[/dim]"
        )
    for module in ev.changed_modules:
        say(f"  changed module: {module}")
    for url in ev.fix_commits:
        say(f"  fix commit: {url}")
    for check in ev.checks_passed:
        say(f"  check passed: {check}")
    for note in ev.notes:
        say(f"  note: {note}")


@app.command("version")
def version_command() -> None:
    """Print the vexproof version."""
    console.print(__version__)
