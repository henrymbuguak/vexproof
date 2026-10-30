"""`vexproof report` on a findings file written by a real prove run, and the scan table."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.codebase import PILLOW
from tests.integration.test_prove import FINDINGS, _setup
from tests.llm_fakes import scripted_stack
from tests.report_fixtures import finding
from vexproof import cli
from vexproof.domain import Verdict
from vexproof.pipeline import ScanResult, prove
from vexproof.report.openvex import problems
from vexproof.service import payload

EXAMPLE = Path(__file__).parents[2] / "examples" / "service_profile.yaml"


def _flat(output: str) -> str:
    return " ".join(output.split())


def _findings_file(tmp_path: Path) -> Path:
    project, analyzers = _setup(tmp_path)
    stack, _ = scripted_stack([], tmp_path / "model")
    proved = prove(project, [PILLOW], FINDINGS, analyzers, stack)
    result = ScanResult(
        source="https://github.com/acme/shop", commit="abc1234", packages=(PILLOW,), findings=proved
    )
    out = tmp_path / "findings.json"
    out.write_text(json.dumps(payload(result)))
    return out


@pytest.fixture
def wide(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.console, "width", 250)


@pytest.mark.usefixtures("wide")
def test_report_command_ranks_plans_and_exports(tmp_path: Path) -> None:
    findings = _findings_file(tmp_path)
    html, vex = tmp_path / "report.html", tmp_path / "vex.json"
    result = CliRunner().invoke(
        cli.app,
        ["report", str(findings), "--profile", str(EXAMPLE), "--html", str(html),
         "--openvex", str(vex), "--author", "Acme", "--top", "2"],
        terminal_width=200,
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    text = _flat(result.output)
    assert "What to fix first, and why" in text
    assert "shop/views.py:11 -> IcoFile.frame (6 hops, all certain)" in text
    assert "... and 1 more (--top 3 to list them all)" in text
    assert "Priority: fix soon 1, review 2, not affected 1" in text.replace("fix now 0, ", "")
    assert "Upgrade plan" in text
    assert "(OpenVEX: 1 affected, 1 not_affected, 2 under_investigation)" in text
    document = json.loads(vex.read_text())
    assert problems(document) == []
    assert document["author"] == "Acme"
    assert document["statements"][0]["products"][0]["@id"] == "pkg:github/acme/shop@abc1234"
    page = html.read_text()
    assert "Which vulnerabilities reach your code" in page
    assert "profile: demo-fixture-app" in page


def test_report_command_errors(tmp_path: Path) -> None:
    runner = CliRunner()
    missing = runner.invoke(cli.app, ["report", str(tmp_path / "nope.json")])
    assert missing.exit_code == 2
    assert "cannot read" in _flat(missing.output)
    findings = _findings_file(tmp_path)
    bad_profile = tmp_path / "p.yaml"
    bad_profile.write_text("- a list\n")
    rejected = runner.invoke(cli.app, ["report", str(findings), "--profile", str(bad_profile)])
    assert rejected.exit_code == 2
    assert "must be a YAML mapping" in _flat(rejected.output)


def test_report_with_everything_cleared(tmp_path: Path) -> None:
    out = tmp_path / "findings.json"
    cleared = finding("GHSA-c", verdict=Verdict.NOT_AFFECTED)
    out.write_text(json.dumps({"findings": [cleared.model_dump(mode="json")]}))
    result = CliRunner().invoke(cli.app, ["report", str(out)], terminal_width=200)
    assert result.exit_code == 0, result.output
    assert "No upgrades needed: every alert is cleared." in _flat(result.output)


@pytest.mark.usefixtures("wide")
def test_scan_table_shows_priority_short_names_and_disputes() -> None:
    reachable = finding("GHSA-r", verdict=Verdict.AFFECTED)
    picked = finding("GHSA-p", picks=("PIL.Image.Image.convert", "PIL.Image.open"),
                     disputed_by="GHSA-rev")  # fmt: skip
    candidates = finding("GHSA-c").model_copy(update={"evidence": None})
    result = ScanResult(
        source="shop", commit=None, packages=(), findings=(picked, reachable, candidates)
    )
    with cli.console.capture() as captured:
        cli._render(result, None)
    text = _flat(captured.get())
    assert text.index("GHSA-r") < text.index("GHSA-p")  # reachable first
    assert "IcoFile.frame <- shop/admin.py:20" in text
    assert "picked Image.convert (+1); disputed by GHSA-rev" in text
    assert "Priority: fix now 0, fix soon 1, review 2, not affected 0" in text
    assert cli._note(finding("GHSA-n", notes=("a note",))) == "a note"
    assert cli._note(finding("GHSA-e", disputed_by="GHSA-x").model_copy(
        update={"evidence": None})) == "disputed by GHSA-x"  # fmt: skip
