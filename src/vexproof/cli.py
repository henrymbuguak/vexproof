"""Command-line interface."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from vexproof import __version__
from vexproof.config import Settings
from vexproof.domain import Finding, ServiceProfile
from vexproof.domain.profile import load_service_profile
from vexproof.errors import VexproofError
from vexproof.ingest.repo import checkout
from vexproof.intel.cache import Cache
from vexproof.intel.http import JsonHttp, make_client
from vexproof.logging import configure_logging
from vexproof.pipeline import IntelConfig, ScanResult, scan

app = typer.Typer(help="Which dependency vulnerabilities actually reach your code, with proof.")
console = Console()


def _sort_key(finding: Finding) -> tuple[bool, float, float, str]:
    s = finding.signals
    return (not s.in_kev, -(s.epss or 0.0), -(s.cvss or 0.0), finding.id)


def _render(result: ScanResult, profile: ServiceProfile | None) -> None:
    table = Table(title=f"Raw findings for {result.source}", show_lines=False)
    for column in ("Package", "Advisory", "Fixed in", "CVSS", "EPSS", "KEV", "Direct", "Note"):
        table.add_column(column)
    for f in sorted(result.findings, key=_sort_key):
        table.add_row(
            f"{f.package.name} {f.package.version}",
            f.advisory.id,
            f.advisory.fixed_in or "-",
            f"{f.signals.cvss:.1f}"
            if f.signals.cvss is not None
            else (f.advisory.severity_label or "-"),
            f"{f.signals.epss:.3f}" if f.signals.epss is not None else "-",
            "yes" if f.signals.in_kev else "",
            "yes" if f.package.direct else "",
            f"disputed by {f.advisory.disputed_by}" if f.advisory.disputed_by else "",
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
    workspace: Annotated[Path, typer.Option(help="Where GitHub repos are cloned")] = Path(
        ".vexproof-cache/repos"
    ),
    log_json: Annotated[bool, typer.Option(help="Emit JSON log lines")] = False,
) -> None:
    """Scan a repository and list its raw scanner alerts with KEV and EPSS attached."""
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
                result = scan(
                    repo_path,
                    http=JsonHttp(client, cache),
                    config=IntelConfig(settings.osv_url, settings.kev_url, settings.epss_url),
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
        payload = {
            "source": result.source,
            "commit": result.commit,
            "packages": [p.model_dump(mode="json") for p in result.packages],
            "findings": [f.model_dump(mode="json") for f in result.findings],
        }
        json_out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        console.print(f"wrote {json_out}")


@app.command("version")
def version_command() -> None:
    """Print the vexproof version."""
    console.print(__version__)
