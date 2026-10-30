"""Command-line interface."""

from __future__ import annotations

import functools
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from vexproof import __version__
from vexproof.config import Settings
from vexproof.domain import Finding, Level, ServiceProfile
from vexproof.domain.profile import load_service_profile
from vexproof.errors import VexproofError
from vexproof.evaluate.markdown import render_markdown, summary_rows
from vexproof.evaluate.score import evaluate, load_observation, load_record
from vexproof.llm.budget import UsageReport
from vexproof.llm.factory import ModelStack, build_stack, list_models
from vexproof.llm.types import ModelError
from vexproof.logging import configure_logging
from vexproof.modelcheck import MIN_ACCURACY, GoldReport, ping, run_gold
from vexproof.pipeline import (
    ScanResult,
    level_counts,
    selection_counts,
    verdict_counts,
)
from vexproof.report.context import ReportContext, short_symbol
from vexproof.report.html import render_html
from vexproof.report.openvex import openvex, problems
from vexproof.report.priority import Ranked, Tier, Upgrade, rank, upgrade_plan
from vexproof.service import ScanRequest, model_config, payload, run_scan
from vexproof.symbols.gold import load_gold

app = typer.Typer(help="Which dependency vulnerabilities actually reach your code, with proof.")
# Advisory text, model output and error messages are untrusted: never let Rich read them as markup
# (a stray "[/b]" crashes, "[link=...]" plants a hidden hyperlink) or as emoji codes (":cloud:").
# Every dynamic value goes through `escape`; markup appears only in literals written here.
console = Console(emoji=False)

LEVEL_LABELS = {
    Level.L0_NOT_IMPORTED.value: "not imported by your code (cleared)",
    Level.L1_SYMBOL.value: "changed functions found: check if your code calls them",
    Level.L2_MODULE.value: "only the changed module is known",
    Level.L3_NONE.value: "needs review: no usable Python fix code",
}


TIER_STYLE = {
    Tier.FIX_NOW: "bold red",
    Tier.FIX_SOON: "yellow",
    Tier.REVIEW: "blue",
    Tier.NOT_AFFECTED: "green",
}


def _note(finding: Finding) -> str:
    """The evidence in a few words; a dispute is always shown, whatever else is known."""
    evidence = finding.evidence
    text = ""
    if evidence and evidence.call_chain:
        start = evidence.call_chain[0]
        text = f"{short_symbol(evidence.call_chain[-1].symbol)} <- {start.file}:{start.line}"
    elif evidence and evidence.vulnerable_symbols:
        text = "picked " + _first(evidence.vulnerable_symbols)
    elif evidence and evidence.candidates:
        text = _first(tuple(c.qualname for c in evidence.candidates))
    elif evidence and evidence.notes:
        text = evidence.notes[-1][:60]
    if finding.advisory.disputed_by:
        text = (text + "; " if text else "") + f"disputed by {finding.advisory.disputed_by}"
    return text


def _first(names: tuple[str, ...]) -> str:
    more = len(names) - 1
    return short_symbol(names[0]) + (f" (+{more})" if more else "")


def _tier_cell(tier: Tier) -> str:
    style = TIER_STYLE[tier]
    return f"[{style}]{tier.value}[/{style}]"


def _render(result: ScanResult, profile: ServiceProfile | None) -> None:
    table = Table(title=f"Findings for {escape(result.source)}", show_lines=False)
    columns = ("Priority", "Level", "Package", "Advisory", "Fixed in", "CVSS", "EPSS", "KEV")
    for column in (*columns, "Evidence"):
        table.add_column(column, overflow="fold")
    ranked = rank(result.findings, profile)
    for item in ranked:
        f = item.finding
        table.add_row(
            _tier_cell(item.tier) if f.evidence else "-",
            f.evidence.level.value if f.evidence else "-",
            escape(f"{f.package.name} {f.package.version}"),
            escape(f.advisory.id),
            escape(f.advisory.fixed_in or "-"),
            f"{f.signals.cvss:.1f}"
            if f.signals.cvss is not None
            else escape(f.advisory.severity_label or "-"),
            f"{f.signals.epss:.3f}" if f.signals.epss is not None else "-",
            "yes" if f.signals.in_kev else "",
            escape(_note(f)),
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
        + (f" | profile: {escape(profile.service)}" if profile else "")
    )
    if result.findings and any(f.evidence for f in result.findings):
        _render_funnel(result.findings)
        _render_tiers(ranked)


def _render_tiers(ranked: list[Ranked], *, hint: bool = True) -> None:
    counts = {tier: sum(1 for r in ranked if r.tier is tier) for tier in Tier}
    console.print(
        "Priority: "
        + ", ".join(f"{_tier_cell(tier)} {count}" for tier, count in counts.items())
        + (" | the plan: [bold]vexproof report[/bold] <findings.json>" if hint else "")
    )


def _render_funnel(findings: tuple[Finding, ...]) -> None:
    counts = level_counts(findings)
    funnel = Table(title=f"Evidence levels for {len(findings)} alerts", show_header=False)
    funnel.add_column("Level")
    funnel.add_column("Meaning")
    funnel.add_column("Alerts", justify="right")
    for level, count in counts.items():
        funnel.add_row(level, LEVEL_LABELS[level], str(count))
    console.print(funnel)
    picked = selection_counts(findings)
    if any(picked.values()):
        console.print(
            f"Symbol selection on L1 alerts: [bold]{picked['picked']} verified picks[/bold], "
            f"{picked['none_match']} where no changed function matches, "
            f"{picked['rejected']} rejected by the verifier, {picked['failed']} failed"
        )
    _render_verdicts(findings)


def _render_verdicts(findings: tuple[Finding, ...]) -> None:
    counts = verdict_counts(findings)
    table = Table(title="Where each alert stands", show_header=False)
    table.add_column("Outcome")
    table.add_column("How it was decided")
    table.add_column("Alerts", justify="right")
    rows = [
        ("cleared", "package never imported by your code", counts["cleared_package"]),
        ("cleared", "vulnerable module never loaded by your code", counts["cleared_module"]),
        ("reachable", "call path from your code, every hop certain", counts["path_certain"]),
        (
            "reachable",
            "call path from your code, uncertain hops reviewed by the model",
            counts["path_reviewed"],
        ),
        ("open", "needs review: no verified evidence either way", counts["open"]),
    ]
    for outcome, how, count in rows:
        table.add_row(outcome, how, str(count))
    console.print(table)
    cleared = counts["cleared_package"] + counts["cleared_module"]
    reachable = counts["path_certain"] + counts["path_reviewed"]
    console.print(
        f"Alert noise reduction: [bold]{100 * cleared / len(findings):.1f}%[/bold] "
        f"({cleared} of {len(findings)} cleared with evidence); "
        f"[bold]{reachable}[/bold] proven reachable with a call path"
    )


def _render_usage(stack: ModelStack, settings: Settings) -> None:
    report: UsageReport = stack.budget.report
    total = report.total
    if not total.calls:
        return
    cost = report.cost_usd(settings.price_input_per_m, settings.price_output_per_m)
    fresh = report.cost_usd(settings.price_input_per_m, settings.price_output_per_m, fresh=True)
    console.print(
        f"Model {escape(stack.label)}: {total.calls} call(s), "
        f"{total.replayed} replayed from recordings, "
        f"{total.input_tokens:,} input + {total.output_tokens:,} output tokens"
        + (f", about ${cost:.4f}" if cost is not None else "")
        + (
            f" (without recordings: about ${fresh:.4f})"
            if fresh is not None and total.replayed
            else ""
        )
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
    html_out: Annotated[
        Path | None, typer.Option("--html", help="Write a self-contained HTML report here")
    ] = None,
    vex_out: Annotated[
        Path | None, typer.Option("--openvex", help="Write an OpenVEX document here")
    ] = None,
    analysis: Annotated[
        bool, typer.Option(help="Analyse imports and fix commits (off: intel only)")
    ] = True,
    model: Annotated[
        bool | None,
        typer.Option(
            "--model/--no-model",
            help="Ask the model to pick vulnerable functions (default: on when one is configured)",
        ),
    ] = None,
    trace: Annotated[
        bool, typer.Option(help="Search for call paths to picked functions (needs the model)")
    ] = True,
    workspace: Annotated[Path, typer.Option(help="Where GitHub repos are cloned")] = Path(
        ".vexproof-cache/repos"
    ),
    log_json: Annotated[bool, typer.Option(help="Emit JSON log lines")] = False,
) -> None:
    """Scan a repository: raw alerts, then the evidence level of each one."""
    configure_logging(json_output=log_json)
    settings = Settings()
    request = ScanRequest(
        target=target,
        commit=commit,
        sbom=sbom,
        analysis=analysis,
        model=model,
        trace=trace,
        workspace=workspace,
    )
    try:
        service_profile = load_service_profile(profile) if profile else None
        outcome = run_scan(settings, request)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except VexproofError as exc:
        console.print(f"[red]error:[/red] {escape(str(exc))}")
        raise typer.Exit(code=2) from exc

    result = outcome.result
    _render(result, service_profile)
    if outcome.stack is not None:
        _render_usage(outcome.stack, settings)
    if json_out:
        document = payload(result, outcome.usage)
        json_out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        console.print(f"wrote {escape(str(json_out))}")
    context = _context(result.source, result.commit, result.findings, service_profile)
    _write_reports(context, html_out, vex_out)


@app.command("show")
def show_command(
    findings_json: Annotated[Path, typer.Argument(help="JSON written by `vexproof scan --json`")],
    advisory: Annotated[str, typer.Argument(help="Advisory id, alias (CVE-...) or finding id")],
) -> None:
    """Explain one alert: its evidence level, candidate functions, fix commits and notes."""
    _, findings = _load_findings(findings_json)
    wanted = advisory.upper()
    matches = [
        f
        for f in findings
        if f.id.upper() == wanted
        or f.advisory.id.upper() == wanted
        or wanted in (a.upper() for a in f.advisory.aliases)
    ]
    if not matches:
        console.print(f"[red]no finding matches {escape(advisory)}[/red]")
        raise typer.Exit(code=1)
    for finding in matches:
        _show(finding)


def _load_findings(path: Path) -> tuple[dict[str, object], tuple[Finding, ...]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data, tuple(Finding.model_validate(f) for f in data["findings"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        console.print(f"[red]error:[/red] cannot read {escape(str(path))}: {escape(str(exc))}")
        raise typer.Exit(code=2) from exc


def _context(
    source: str,
    commit: str | None,
    findings: tuple[Finding, ...],
    profile: ServiceProfile | None,
) -> ReportContext:
    return ReportContext(
        source=source,
        commit=commit,
        findings=findings,
        generated_at=datetime.now(UTC).replace(microsecond=0),
        tooling=f"vexproof {__version__}",
        profile=profile,
    )


def _write_reports(
    context: ReportContext, html_out: Path | None, vex_out: Path | None, author: str = "vexproof"
) -> None:
    if html_out:
        html_out.write_text(render_html(context), encoding="utf-8")
        console.print(f"wrote {escape(str(html_out))}")
    if vex_out:
        document = openvex(context, author=author)
        broken = problems(document)
        if broken:  # pragma: no cover - guarded by tests; never write an invalid document
            raise VexproofError(f"OpenVEX document is invalid: {broken[0]}")
        vex_out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        statuses = [s["status"] for s in document["statements"]]
        counts = ", ".join(f"{statuses.count(x)} {x}" for x in sorted(set(statuses)))
        console.print(f"wrote {escape(str(vex_out))} (OpenVEX: {escape(counts)})")


@app.command("report")
def report_command(
    findings_json: Annotated[Path, typer.Argument(help="JSON written by `vexproof scan --json`")],
    profile: Annotated[Path | None, typer.Option(help="Service profile YAML")] = None,
    html_out: Annotated[
        Path | None, typer.Option("--html", help="Write a self-contained HTML report here")
    ] = None,
    vex_out: Annotated[
        Path | None, typer.Option("--openvex", help="Write an OpenVEX document here")
    ] = None,
    author: Annotated[str, typer.Option(help="OpenVEX author")] = "vexproof",
    top: Annotated[int, typer.Option(help="Alerts to list in the terminal")] = 15,
) -> None:
    """What to fix first and why, the upgrade that clears it, and OpenVEX/HTML exports."""
    data, findings = _load_findings(findings_json)
    try:
        service_profile = load_service_profile(profile) if profile else None
        context = _context(
            str(data.get("source") or findings_json.stem),
            str(data["commit"]) if data.get("commit") else None,
            findings,
            service_profile,
        )
        ranked = rank(findings, service_profile)
        _render_priorities(ranked, top)
        _render_upgrades(upgrade_plan(ranked))
        _write_reports(context, html_out, vex_out, author)
    except VexproofError as exc:
        console.print(f"[red]error:[/red] {escape(str(exc))}")
        raise typer.Exit(code=2) from exc


def _render_priorities(ranked: list[Ranked], top: int) -> None:
    table = Table(title="What to fix first, and why")
    for column in ("Priority", "Advisory", "Package", "Fixed in", "Why"):
        table.add_column(column, overflow="fold")
    standing = [r for r in ranked if r.tier is not Tier.NOT_AFFECTED]
    for item in standing[:top]:
        f = item.finding
        why = item.brief
        if f.advisory.disputed_by and "disputed" not in why:
            why += f"; disputed by {f.advisory.disputed_by}"
        table.add_row(
            _tier_cell(item.tier),
            escape(f.advisory.id),
            escape(f"{f.package.name} {f.package.version}"),
            escape(f.advisory.fixed_in or "-"),
            escape(why),
        )
    console.print(table)
    hidden = len(standing) - min(top, len(standing))
    if hidden:
        console.print(f"... and {hidden} more (--top {len(standing)} to list them all)")
    _render_tiers(ranked, hint=False)


def _render_upgrades(plans: list[Upgrade]) -> None:
    if not plans:
        console.print("No upgrades needed: every alert is cleared.")
        return
    table = Table(title="Upgrade plan")
    for column in ("Priority", "Package", "Installed", "Clears reachable", "Clears all", "Notes"):
        table.add_column(column, overflow="fold")
    for plan in plans:
        notes = [f"resolves {len(plan.resolves)}"]
        if plan.no_fix:
            notes.append(f"{len(plan.no_fix)} without a fix")
        if plan.major_jump:
            notes.append("major version change")
        table.add_row(
            _tier_cell(plan.tier),
            escape(plan.package),
            escape(plan.installed),
            escape(f">= {plan.reachable_target}" if plan.reachable_target else "-"),
            escape(f">= {plan.target}" if plan.target else "-"),
            escape(", ".join(notes)),
        )
    console.print(table)


def _show(f: Finding) -> None:
    """Print one finding; long lines (URLs, qualnames) soft-wrap so they stay copyable."""
    say = functools.partial(console.print, soft_wrap=True)
    adv, ev = f.advisory, f.evidence
    console.rule(escape(f"{adv.id} in {f.package.name} {f.package.version}"))
    say(f"[bold]{escape(adv.summary or '(no summary)')}[/bold]")
    aliases = ", ".join(adv.aliases) or "-"
    say(escape(f"aliases: {aliases} | fixed in: {adv.fixed_in or '-'}"))
    signals = f.signals
    say(
        escape(
            f"CVSS {signals.cvss if signals.cvss is not None else '-'} | "
            f"EPSS {signals.epss if signals.epss is not None else '-'} | "
            f"KEV {'yes' if signals.in_kev else 'no'}"
            + (f" | disputed by {adv.disputed_by}" if adv.disputed_by else "")
        )
    )
    if ev is None:
        say("no evidence yet (scan was run with --no-analysis)")
        return
    verdict = f.verdict.value if f.verdict else "pending"
    say(f"evidence level: [bold]{ev.level.value}[/bold] ({LEVEL_LABELS[ev.level.value]})")
    say(escape(f"verdict: {verdict}" + (f" ({f.justification})" if f.justification else "")))
    if ev.vulnerable_symbols:
        picked = escape(", ".join(ev.vulnerable_symbols))
        say(f"[bold]picked:[/bold] {picked}  [dim]({escape(ev.symbol_model or '')})[/dim]")
    if ev.symbol_quote:
        say(escape(f'  advisory says: "{ev.symbol_quote}"'))
    if ev.call_chain:
        how = (
            f"uncertain hops reviewed by {ev.chain_model}" if ev.chain_model else "all hops certain"
        )
        say(f"[bold]call path from your code[/bold] [dim]({escape(how)})[/dim]")
        for i, hop in enumerate(ev.call_chain):
            mark = "  " if hop.certain else "? "
            via = "" if i == 0 else f" via {hop.via}"
            where = escape(f"{hop.file}:{hop.line}{via}")
            say(f"  {mark}{escape(hop.symbol)}  [dim]{where}[/dim]")
    for candidate in ev.candidates:
        commits = ", ".join(candidate.commits)
        say(
            f"  candidate: {escape(candidate.qualname)}  [dim]{escape(candidate.file)}, "
            f"{candidate.changed_lines} changed line(s), commits {escape(commits)}[/dim]"
        )
    for module in ev.changed_modules:
        say(escape(f"  changed module: {module}"))
    for url in ev.fix_commits:
        say(escape(f"  fix commit: {url}"))
    for check in ev.checks_passed:
        say(escape(f"  check passed: {check}"))
    for note in ev.notes:
        say(escape(f"  note: {note}"))


@app.command("check-model")
def check_model_command(
    findings_json: Annotated[
        Path | None,
        typer.Argument(help="JSON from `vexproof scan --json` to run the gold symbol test on"),
    ] = None,
    gold: Annotated[Path, typer.Option(help="Gold labels for symbol selection")] = Path(
        "eval/gold/symbols.yaml"
    ),
) -> None:
    """Go/no-go for the Model API: key, models, structured output, then the gold symbol test."""
    configure_logging()
    settings = Settings()
    config = model_config(settings)
    say = functools.partial(console.print, soft_wrap=True)
    say(escape(f"endpoint: {config.base_url} | model: {config.model} | api: {config.api}"))
    if config.local:
        say("local model server: no API key needed")
    elif not config.api_key:
        say("[red]NO-GO[/red]: MODEL_API_KEY is not set (add it to .env)")
        raise typer.Exit(code=1)
    try:
        models = list_models(config.api_key or "local", config.base_url)
        say(escape(f"models available: {', '.join(models) or '(none listed)'}"))
        if models and config.model not in models and f"{config.model}:latest" not in models:
            model = escape(config.model)
            say(f"[yellow]warning[/yellow]: {model} is not in that list; set VEXPROOF_MODEL")
    except ModelError as exc:
        say(f"[yellow]warning[/yellow]: {escape(str(exc))}")

    result = ping(
        lambda api: build_stack(model_config(settings, api=api, mode="live")), prefer=config.api
    )
    for api, error in result.errors.items():
        say(f"  {api} API: [red]failed[/red]: {escape(error)}")
    if result.api is None:
        say("[red]NO-GO[/red]: structured output works on neither API")
        raise typer.Exit(code=1)
    say(f"structured output: [green]ok[/green] on the {result.api} API")
    if result.api != config.api:
        say(f"  set VEXPROOF_MODEL_API={result.api} in .env")
    if findings_json is None:
        say("connection: [green]GO[/green]. Next: scan with --no-model --json, then pass that file")
        return

    try:
        data = json.loads(findings_json.read_text(encoding="utf-8"))
        findings = [Finding.model_validate(f) for f in data["findings"]]
        cases = load_gold(gold)
        stack = build_stack(model_config(settings, api=result.api))
        report = run_gold(cases, findings, stack)
    except (OSError, ValueError, KeyError) as exc:
        console.print(
            f"[red]error:[/red] cannot read {escape(str(findings_json))}: {escape(str(exc))}"
        )
        raise typer.Exit(code=2) from exc
    except VexproofError as exc:
        console.print(f"[red]error:[/red] {escape(str(exc))}")
        raise typer.Exit(code=2) from exc
    _render_gold(report)
    _render_usage(stack, settings)
    if not report.go:
        raise typer.Exit(code=1)


def _render_gold(report: GoldReport) -> None:
    table = Table(title="Gold symbol-selection test")
    for column in ("Advisory", "Result", "Model answer", "Detail"):
        table.add_column(column, overflow="fold")
    colour = {"correct": "green", "wrong": "red", "rejected": "red"}
    for row in report.rows:
        style = colour.get(row.result, "yellow")
        table.add_row(
            escape(row.case.advisory),
            f"[{style}]{row.result}[/{style}]",
            escape(", ".join(row.selected) or "-"),
            escape(row.detail[:120]),
        )
    console.print(table)
    missing = report.count("missing")
    console.print(
        f"{report.count('correct')}/{report.scored} correct ({100 * report.accuracy:.0f}%, "
        f"need {100 * MIN_ACCURACY:.0f}%), {report.hallucinations} invented name(s), "
        f"{report.count('error')} error(s)"
        + (f", {missing} gold case(s) not in this findings file" if missing else "")
    )
    verdict = "[green]GO[/green]" if report.go else "[red]NO-GO[/red]"
    console.print(f"verdict: {verdict}")


@app.command("eval")
def eval_command(
    findings_json: Annotated[Path, typer.Argument(help="JSON written by `vexproof scan --json`")],
    observed: Annotated[
        Path, typer.Option(help="Observation from eval/dynamic/observe.py (the oracle)")
    ],
    gold: Annotated[
        Path | None, typer.Option(help="Gold labels for function picks (optional)")
    ] = None,
    markdown: Annotated[Path | None, typer.Option(help="Write the evaluation here")] = None,
) -> None:
    """Check a scan against a run of the real project: wrong clears, confirmed paths, cost."""
    try:
        record = load_record(json.loads(findings_json.read_text(encoding="utf-8")))
        observation = load_observation(json.loads(observed.read_text(encoding="utf-8")))
        cases = load_gold(gold) if gold else ()
    except (OSError, ValueError) as exc:
        console.print(f"[red]error:[/red] cannot read input: {escape(str(exc))}")
        raise typer.Exit(code=2) from exc
    except VexproofError as exc:
        console.print(f"[red]error:[/red] {escape(str(exc))}")
        raise typer.Exit(code=2) from exc
    result = evaluate(record, observation, cases)
    table = Table(title=f"Evaluation against {escape(observation.workload)}", show_header=False)
    table.add_column("Measure")
    table.add_column("Result")
    for measure, value in summary_rows(result):
        table.add_row(escape(measure), escape(value))
    console.print(table)
    for check in result.falsified:
        loaded = ", ".join(check.loaded)
        console.print(
            f"[red]wrong clear[/red] {escape(check.finding.advisory.id)}: {escape(loaded)}"
        )
    for module in result.closure.missed if result.closure else ():
        console.print(f"[red]missing from the closure[/red] {escape(module)}")
    if markdown:
        markdown.write_text(render_markdown(result), encoding="utf-8")
        console.print(f"wrote {escape(str(markdown))}")
    if result.sound:
        console.print("verdict: [green]sound[/green] (no clear contradicted by the run)")
    else:
        console.print("verdict: [red]UNSOUND[/red]")
        raise typer.Exit(code=1)


@app.command("serve")
def serve_command(
    host: Annotated[str, typer.Option(help="Interface to listen on")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port to listen on")] = 8000,
) -> None:
    """Start the web app: run scans from the browser and read their results."""
    try:
        import uvicorn  # noqa: PLC0415 - the web group is optional

        from vexproof.web.app import create_app  # noqa: PLC0415
    except ImportError as exc:
        console.print("[red]error:[/red] the web app needs its extras: uv sync --group web")
        raise typer.Exit(code=2) from exc
    configure_logging()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        console.print(
            "[yellow]note:[/yellow] listening beyond this computer. Anyone who can reach it can "
            "start scans, which clone repositories and may call your model API."
        )
    console.print(f"vexproof web app on http://{escape(host)}:{port}")
    uvicorn.run(create_app(), host=host, port=port, log_level="warning")


@app.command("version")
def version_command() -> None:
    """Print the vexproof version."""
    console.print(__version__)
