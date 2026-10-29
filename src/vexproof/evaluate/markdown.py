"""The evaluation as Markdown, for the README and the write-up."""

from __future__ import annotations

from vexproof.evaluate.score import Evaluation


def _pct(part: int, whole: int) -> str:
    return f"{100 * part / whole:.1f}%" if whole else "-"


def summary_rows(ev: Evaluation) -> list[tuple[str, str]]:
    """(measure, result) pairs shared by the terminal table and the Markdown."""
    cleared = len(ev.clears)
    reachable = len(ev.paths)
    rows = [
        ("Alerts", str(ev.alerts)),
        (
            "Decided with evidence",
            f"{ev.decided} ({_pct(ev.decided, ev.alerts)}): {cleared} cleared, "
            f"{reachable} reachable",
        ),
    ]
    checkable = [c for c in ev.clears if c.status != "uncheckable"]
    package_level = cleared - len(checkable)
    note = f" ({package_level} package-level, checked via the closure)" if package_level else ""
    rows.append(
        (
            "Clears contradicted by the run (module loaded)",
            f"{len(ev.falsified)} of {len(checkable)}{note}",
        )
    )
    if ev.closure is not None:
        native = len(ev.closure.not_in_source)
        rows.append(
            (
                "Modules loaded at run time but missing from the closure",
                f"{len(ev.closure.missed)} of {ev.closure.loaded}"
                + (f" (plus {native} compiled extension(s) with no source)" if native else ""),
            )
        )
    unexercised = reachable - len(ev.confirmed)
    note = f" ({unexercised} not exercised by the workload)" if unexercised else ""
    rows.append(
        (
            "Reachable alerts whose vulnerable function ran",
            f"{len(ev.confirmed)} of {reachable}{note}",
        )
    )
    rows.append(("Open alerts whose picked function ran", str(len(ev.executed_open))))
    if ev.gold:
        right = sum(c.correct for c in ev.gold)
        rows.append(("Function picks matching gold labels", f"{right} of {len(ev.gold)}"))
    if ev.cost_usd is not None:
        rows.append(
            (
                "Model cost of a scan without recordings"
                if ev.cost_is_fresh
                else "Model cost of this scan (replayed answers not counted)",
                f"${ev.cost_usd:.4f} total, ${ev.cost_usd / max(ev.alerts, 1):.5f} per alert",
            )
        )
    if ev.scan_seconds:
        rows.append(("Scan time", f"{ev.scan_seconds:.0f} s"))
    return rows


def render_markdown(ev: Evaluation) -> str:
    record, obs = ev.record, ev.observation
    commit = f" @ `{record.commit[:12]}`" if record.commit else ""
    versions = ", ".join(f"{k} {v}" for k, v in sorted(obs.packages.items()) if k in _SHOWN)
    lines = [
        f"# Evaluation: {record.source}{commit}",
        "",
        f"Oracle: the project run under `{obs.workload}` ({len(obs.steps)} steps) on Python "
        f"{obs.python}" + (f" with {versions}" if versions else "") + ". "
        f"{len(obs.loaded_modules)} modules loaded, {len(obs.executed_functions)} functions ran.",
        "",
        f"**Verdict: {'sound' if ev.sound else 'UNSOUND'}** — "
        + (
            "no clear was contradicted and every loaded module was in the closure."
            if ev.sound
            else "see the failures below."
        ),
        "",
        "| Measure | Result |",
        "| --- | --- |",
        *(f"| {m} | {r} |" for m, r in summary_rows(ev)),
        "",
        "## Reachable alerts",
        "",
        "| Advisory | Vulnerable function | Ran under the workload |",
        "| --- | --- | --- |",
        *(
            f"| {p.finding.advisory.id} | `{p.target}` | "
            f"{'yes' if p.status == 'confirmed' else 'not exercised'} |"
            for p in ev.paths
        ),
        "",
        "## Cleared alerts",
        "",
        "| Advisory | Module(s) the clear rests on | Loaded at run time |",
        "| --- | --- | --- |",
        *(
            f"| {c.finding.advisory.id} | {', '.join(f'`{m}`' for m in c.modules) or '(package)'}"
            f" | {_clear_cell(c.status, c.loaded)} |"
            for c in ev.clears
        ),
    ]
    if ev.closure and (ev.closure.missed or ev.closure.not_in_source):
        lines += ["", "## Loaded but not in the closure", ""]
        lines += [f"- `{m}` (soundness failure)" for m in ev.closure.missed]
        lines += [f"- `{m}` (compiled extension: no source to scan)"
                  for m in ev.closure.not_in_source]  # fmt: skip
    if ev.executed_open:
        lines += [
            "",
            "## Open alerts whose picked function ran",
            "",
            "Leads the path search missed; running a function does not by itself mean the "
            "vulnerable input can reach it.",
            "",
        ]
        lines += [
            f"- {f.advisory.id}: `{', '.join(f.evidence.vulnerable_symbols)}`"
            for f in ev.executed_open
            if f.evidence
        ]
    if ev.gold:
        lines += ["", "## Function picks against gold labels", ""]
        lines += [
            f"- {g.case.advisory}: {'correct' if g.correct else 'WRONG'} "
            f"(picked {', '.join(g.picked) or 'none'})"
            for g in ev.gold
        ]
    lines += ["", "## What this does and does not show", "", *_CAVEATS]
    return "\n".join(lines) + "\n"


def _clear_cell(status: str, loaded: tuple[str, ...]) -> str:
    if status == "falsified":
        return "**yes: wrong clear** (" + ", ".join(loaded) + ")"
    return "no" if status == "consistent" else "checked via the closure"


_SHOWN = {"django", "pillow", "flask", "fastapi", "requests", "jinja2", "werkzeug"}
_CAVEATS = [
    "- A run can falsify a clear (the module loaded) but cannot prove one: a module that did "
    "not load under this workload might load under another. The closure check is the stronger "
    "test: every module that loaded must be one the scan said could load.",
    "- A vulnerable function that ran shows the call path is real, not that an exploit works: "
    "conditions inside functions are not modelled. One that did not run was not exercised by "
    "this workload; it is not evidence against the path.",
    "- The oracle runs the project on the Python version noted above, with the exact package "
    "versions the scan analysed.",
]
