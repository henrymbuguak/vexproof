"""A self-contained HTML report: one file, no scripts, no external requests.

Every value that came from outside (advisory text, model notes, file paths) goes through
`html.escape`, links are emitted only for https URLs, and a Content-Security-Policy forbids
scripts, so a hostile advisory cannot run code in the reader's browser.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from html import escape
from urllib.parse import quote

from vexproof.domain import Finding
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

CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'"
TIER_CLASS = {
    Tier.FIX_NOW: "now",
    Tier.FIX_SOON: "soon",
    Tier.REVIEW: "review",
    Tier.NOT_AFFECTED: "clear",
}
MAX_NOTE = 600

STYLE = """
:root{--bg:#fbfaf8;--fg:#1d1c1a;--muted:#6b6862;--line:#e4e1db;--card:#ffffff;
--now:#b42318;--now-bg:#fdecea;--soon:#a15c07;--soon-bg:#fdf3e1;--review:#3d5a80;
--review-bg:#e9eff7;--clear:#2f6f4e;--clear-bg:#e6f2ea;--code:#f2f0ec}
@media (prefers-color-scheme:dark){:root{--bg:#161514;--fg:#ecebe8;--muted:#a19e98;
--line:#33312e;--card:#1e1d1b;--now:#ff8a7a;--now-bg:#3a1d19;--soon:#f0b45c;--soon-bg:#35280f;
--review:#9dbbe0;--review-bg:#1c2633;--clear:#7fcf9f;--clear-bg:#15291e;--code:#262522}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px;letter-spacing:-.01em}
h2{font-size:18px;margin:40px 0 4px}
p.lead,p.sub{color:var(--muted);margin:0 0 12px}
a{color:inherit}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.meta{color:var(--muted);font-size:13px;overflow-wrap:anywhere}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:24px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.tile b{display:block;font-size:28px;font-variant-numeric:tabular-nums}
.tile span{color:var(--muted);font-size:13px}
.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;vertical-align:top;padding:10px 12px;border-bottom:1px solid var(--line)}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);
font-weight:600}
tr:last-child td{border-bottom:0}
td.num{font-variant-numeric:tabular-nums;white-space:nowrap}
.badge{display:inline-block;border-radius:999px;padding:1px 9px;font-size:12px;font-weight:600;
white-space:nowrap}
.now{color:var(--now);background:var(--now-bg)}.soon{color:var(--soon);background:var(--soon-bg)}
.review{color:var(--review);background:var(--review-bg)}
.clear{color:var(--clear);background:var(--clear-bg)}
ul.reasons{margin:4px 0 0;padding-left:18px;color:var(--muted);font-size:13px}
details{margin-top:6px}summary{cursor:pointer;color:var(--muted);font-size:13px}
ol.path{margin:8px 0;padding-left:22px}
ol.path li{margin:2px 0;overflow-wrap:anywhere}
.uncertain{color:var(--soon)}
.ev{background:var(--code);border-radius:8px;padding:10px 12px;margin-top:6px;font-size:13px;
overflow-wrap:anywhere}
.ev p{margin:4px 0}
td.mono{white-space:nowrap}.lbl{display:none}
@media (max-width:720px){thead{display:none}tr{display:block;border-bottom:1px solid var(--line);
padding:8px 0}tr:last-child{border-bottom:0}td{display:block;border:0;padding:3px 12px}
.lbl{display:inline}}
footer{margin-top:48px;color:var(--muted);font-size:13px;border-top:1px solid var(--line);
padding-top:16px}
"""


def render_html(context: ReportContext) -> str:
    ranked = rank(context.findings, context.profile)
    by_tier = {tier: [r for r in ranked if r.tier is tier] for tier in Tier}
    parts = [
        _header(context),
        _tiles(context.findings),
        _section(
            "Fix first",
            "Proven reachable: a verified call path runs from your code to the vulnerable "
            "function. Ordered by exploit signals and your service profile.",
            [*by_tier[Tier.FIX_NOW], *by_tier[Tier.FIX_SOON]],
            "Nothing proven reachable.",
        ),
        _upgrades(upgrade_plan(ranked)),
        _section(
            "Needs review",
            "No verified evidence either way. Known-exploited and severe alerts first.",
            by_tier[Tier.REVIEW],
            "Nothing left open.",
        ),
        _section(
            "Not affected",
            "Cleared with evidence: the vulnerable code is never loaded by your code.",
            by_tier[Tier.NOT_AFFECTED],
            "Nothing cleared.",
        ),
        _footer(context),
    ]
    title = escape(f"vexproof report: {context.source}")
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        f"<title>{title}</title><style>{STYLE}</style></head><body><main>"
        + "".join(parts)
        + "</main></body></html>\n"
    )


def _header(context: ReportContext) -> str:
    commit = f" at <code>{escape(context.commit[:12])}</code>" if context.commit else ""
    profile = context.profile
    if profile is None:
        prof = "no service profile: priorities use exploit signals and severity only"
    else:
        traits = [
            "internet-facing" if profile.internet_facing else "internal",
            f"{profile.criticality} criticality",
            "handles personal data" if profile.handles_personal_data else "",
        ]
        prof = f"profile: {profile.service} ({', '.join(t for t in traits if t)})"
    generated = context.generated_at.strftime("%Y-%m-%d %H:%M UTC")
    return (
        "<header><h1>Which vulnerabilities reach your code</h1>"
        f'<p class="meta">{_link(context.source)}{commit} · {escape(generated)} · '
        f"{escape(prof)}</p></header>"
    )


def _tiles(findings: Sequence[Finding]) -> str:
    counts = outcome_counts(findings)
    cleared = counts[Outcome.CLEARED_PACKAGE] + counts[Outcome.CLEARED_MODULE]
    reachable = counts[Outcome.PATH_CERTAIN] + counts[Outcome.PATH_REVIEWED]
    share = f"{100 * cleared / len(findings):.1f}%" if findings else "-"
    tiles = [
        (str(len(findings)), "scanner alerts"),
        (str(reachable), f"reachable ({counts[Outcome.PATH_CERTAIN]} with every hop certain)"),
        (str(cleared), "not affected, with evidence"),
        (str(counts[Outcome.OPEN]), "open: needs review"),
        (share, "alert noise removed"),
    ]
    body = "".join(f'<div class="tile"><b>{v}</b><span>{escape(t)}</span></div>' for v, t in tiles)
    return f'<section class="tiles">{body}</section>'


def _section(title: str, lead: str, rows: Sequence[Ranked], empty: str) -> str:
    head = f'<h2>{escape(title)} <span class="meta">({len(rows)})</span></h2>'
    head += f'<p class="sub">{escape(lead)}</p>'
    if not rows:
        return f"<section>{head}<p>{escape(empty)}</p></section>"
    header = "".join(
        f"<th>{h}</th>" for h in ("Priority", "Advisory", "Package", "Fixed in", "Why")
    )
    body = "".join(_row(r) for r in rows)
    return (
        f'<section>{head}<div class="scroll"><table><thead><tr>{header}</tr></thead>'
        f"<tbody>{body}</tbody></table></div></section>"
    )


def _row(item: Ranked) -> str:
    f = item.finding
    adv = f.advisory
    advisory = _link(f"https://osv.dev/vulnerability/{quote(adv.id, safe='')}", adv.id)
    summary = f"<div>{escape(adv.summary)}</div>" if adv.summary else ""
    reasons = "".join(f"<li>{escape(r)}</li>" for r in item.reasons[1:])
    return (
        f'<tr id="{escape(f.id)}"><td><span class="badge {TIER_CLASS[item.tier]}">'
        f"{escape(item.tier.value)}</span></td>"
        f'<td class="mono">{advisory}</td>'
        f'<td class="num">{escape(f.package.name)} {escape(f.package.version)}</td>'
        f'<td class="num"><span class="lbl">fixed in </span>{escape(adv.fixed_in or "-")}</td>'
        f"<td>{summary}<div><strong>{escape(item.headline)}</strong></div>"
        f'<ul class="reasons">{reasons}</ul>{_evidence(f)}</td></tr>'
    )


def _evidence(finding: Finding) -> str:
    ev = finding.evidence
    if ev is None:
        return ""
    parts: list[str] = []
    if ev.call_chain:
        steps = []
        for i, hop in enumerate(ev.call_chain):
            via = "" if i == 0 else f" via {hop.via}"
            mark = "" if hop.certain else ' <span class="uncertain">(uncertain, reviewed)</span>'
            steps.append(
                f"<li><code>{escape(hop.symbol)}</code> "
                f'<span class="meta">{escape(f"{hop.file}:{hop.line}{via}")}</span>{mark}</li>'
            )
        parts.append(f'<ol class="path">{"".join(steps)}</ol>')
    if ev.vulnerable_symbols:
        model = f" ({escape(ev.symbol_model)})" if ev.symbol_model else ""
        names = ", ".join(f"<code>{escape(s)}</code>" for s in ev.vulnerable_symbols)
        parts.append(f"<p>vulnerable function: {names}{model}</p>")
    if ev.symbol_quote:
        parts.append(f"<p>advisory says: “{escape(ev.symbol_quote)}”</p>")
    parts.extend(f"<p>{escape(_clip(note))}</p>" for note in ev.notes)
    parts.extend(f"<p>fix commit: {_link(url)}</p>" for url in ev.fix_commits)
    if finding.advisory.disputed_by:
        parts.append(f"<p>disputed by {escape(finding.advisory.disputed_by)}</p>")
    label = "call path and evidence" if ev.call_chain else "evidence"
    return f'<details><summary>{label} ({escape(ev.level.value)})</summary><div class="ev">' + (
        "".join(parts) + "</div></details>"
    )


def _upgrades(plans: Sequence[Upgrade]) -> str:
    head = (
        f'<h2>Upgrade plan <span class="meta">({len(plans)})</span></h2>'
        '<p class="sub">The smallest version of each package that resolves its alerts. Cleared '
        "alerts need no upgrade and are not counted.</p>"
    )
    if not plans:
        return f"<section>{head}<p>No upgrades needed.</p></section>"
    header = "".join(
        f"<th>{h}</th>"
        for h in ("Priority", "Package", "Installed", "Clears reachable", "Clears all", "Notes")
    )
    rows = []
    for plan in plans:
        notes = [f"resolves {len(plan.resolves)} alert(s)"]
        if plan.no_fix:
            notes.append(f"{len(plan.no_fix)} with no fixed version: {', '.join(plan.no_fix)}")
        if plan.major_jump:
            notes.append("major version change: read the release notes")
        if plan.already_cleared:
            notes.append(f"{plan.already_cleared} more already cleared")
        rows.append(
            f'<tr><td><span class="badge {TIER_CLASS[plan.tier]}">{escape(plan.tier.value)}'
            f"</span></td><td>{escape(plan.package)}</td>"
            f'<td class="num">{escape(plan.installed)}</td>'
            f'<td class="num">{escape(_at_least(plan.reachable_target))}</td>'
            f'<td class="num">{escape(_at_least(plan.target))}</td>'
            f"<td>{escape('; '.join(notes))}</td></tr>"
        )
    return (
        f'<section>{head}<div class="scroll"><table><thead><tr>{header}</tr></thead>'
        f"<tbody>{''.join(rows)}</tbody></table></div></section>"
    )


def _footer(context: ReportContext) -> str:
    lines: Iterable[str] = (
        "How to read this: “reachable” means vexproof verified every step of a call path from "
        "your code to the function the fix changed; uncertain steps were judged by the model and "
        "are marked. “Not affected” means the module holding that function is never loaded. "
        "Neither is a guess: the model proposes, the verifier proves.",
        "Paths ignore runtime conditions (configuration, input values), so a reachable alert is "
        "a strong lead for a fix, not proof of an exploit.",
        f"Generated by {context.tooling}. OpenVEX: vexproof report --openvex.",
    )
    return "<footer>" + "".join(f"<p>{escape(line)}</p>" for line in lines) + "</footer>"


def _link(url: str, text: str | None = None) -> str:
    label = escape(text if text is not None else url)
    if not url.startswith("https://"):
        return label
    return f'<a href="{escape(url, quote=True)}" rel="noopener noreferrer">{label}</a>'


def _at_least(version: str | None) -> str:
    return f">= {version}" if version else "-"


def _clip(text: str) -> str:
    return text if len(text) <= MAX_NOTE else text[: MAX_NOTE - 3] + "..."
