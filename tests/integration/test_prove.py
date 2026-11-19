"""The prove stage end to end on the synthetic codebase, and how its results are shown."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from typer.testing import CliRunner

from tests.codebase import FRAME, LIBRARY, PILLOW, write_project
from tests.llm_fakes import scripted_stack
from tests.trees import make_tree
from vexproof import cli
from vexproof.domain import Advisory, Candidate, Evidence, Finding, Level, Package, Verdict
from vexproof.pipeline import Analyzers, ScanResult, prove, verdict_counts
from vexproof.service import payload
from vexproof.sources.tree import SourceTree


class _Store:
    def __init__(self, trees: dict[Package, SourceTree]) -> None:
        self._trees = trees

    def get_many(
        self, packages: Sequence[Package], workers: int = 8
    ) -> tuple[dict[Package, SourceTree], dict[Package, str]]:
        return {p: self._trees[p] for p in packages if p in self._trees}, {}


def _finding(advisory: str, *picks: str, none_match: bool = False) -> Finding:
    candidates = tuple(
        Candidate(qualname=q, module=q.rsplit(".", 2)[0] if "Ico" in q else q.rsplit(".", 1)[0],
                  file="f.py", changed_lines=1)
        for q in (picks or ("PIL.ImageColor.getrgb",))
    )  # fmt: skip
    return Finding(
        id=f"pillow@9.0.0:{advisory}",
        package=PILLOW,
        advisory=Advisory(id=advisory, summary=f"{advisory} summary"),
        evidence=Evidence(
            level=Level.L1_SYMBOL,
            candidates=candidates,
            vulnerable_symbols=() if none_match else picks,
            symbol_model="fake-model / symbol_pick.v1",
        ),
    )


def _setup(tmp_path: Path) -> tuple[Path, Analyzers]:
    tree = make_tree(tmp_path / "sources", PILLOW, LIBRARY)
    project = write_project(tmp_path / "project")
    return project, Analyzers(store=_Store({PILLOW: tree}), fetcher=None)  # type: ignore[arg-type]


FINDINGS = [
    _finding("GHSA-math", "PIL.ImageMath.eval"),
    _finding("GHSA-frame", FRAME),
    _finding("GHSA-none", none_match=True),
    _finding("GHSA-save", "PIL.IcoPlugin._save"),
]


def test_prove_clears_traces_and_leaves_open(tmp_path: Path) -> None:
    project, analyzers = _setup(tmp_path)
    stack, live = scripted_stack([], tmp_path / "model")
    result = {f.advisory.id: f for f in prove(project, [PILLOW], FINDINGS, analyzers, stack)}
    assert live.requests == []  # certain paths and module clears need no model

    assert result["GHSA-math"].verdict is Verdict.NOT_AFFECTED
    frame = result["GHSA-frame"]
    assert frame.verdict is Verdict.AFFECTED
    assert frame.evidence is not None
    assert frame.evidence.call_chain[0].symbol == "shop.views.thumbnail"
    assert frame.evidence.chain_model is None  # nothing needed reviewing
    assert "call_path_verified" in frame.evidence.checks_passed
    assert frame.evidence.notes[-1].endswith("6 hops, all certain")
    assert result["GHSA-none"].verdict is None
    save = result["GHSA-save"]
    assert save.verdict is None
    assert save.evidence is not None
    assert "no call path from your code" in save.evidence.notes[-1]

    counts = verdict_counts(list(result.values()))
    assert counts == {
        "cleared_package": 0,
        "cleared_module": 1,
        "path_certain": 1,
        "path_reviewed": 0,
        "open": 2,
    }


def test_prove_without_model_or_tracing(tmp_path: Path) -> None:
    project, analyzers = _setup(tmp_path)
    stack, _ = scripted_stack([], tmp_path / "model")
    for result in (
        prove(project, [PILLOW], FINDINGS, analyzers),
        prove(project, [PILLOW], FINDINGS, analyzers, stack, trace=False),
    ):
        verdicts = {f.advisory.id: f.verdict for f in result}
        assert verdicts["GHSA-math"] is Verdict.NOT_AFFECTED  # module clears need no model
        assert verdicts["GHSA-frame"] is None


def test_budget_exhaustion_stops_tracing(tmp_path: Path) -> None:
    project, analyzers = _setup(tmp_path)
    library = {**LIBRARY, "PIL/IcoPlugin.py": LIBRARY["PIL/IcoPlugin.py"].replace(
        'Image.register_open("ICO", IcoImageFile)\n', "")}  # fmt: skip
    analyzers = Analyzers(
        store=_Store({PILLOW: make_tree(tmp_path / "loose", PILLOW, library)}),  # type: ignore[arg-type]
        fetcher=None,  # type: ignore[arg-type]
    )
    stack, _ = scripted_stack(
        lambda _: {"action": "callers", "avoid": [], "through": [], "symbol": FRAME, "reason": ""},
        tmp_path / "model",
        max_tokens=1,
    )
    result = prove(project, [PILLOW], FINDINGS, analyzers, stack)
    frame = next(f for f in result if f.advisory.id == "GHSA-frame")
    assert frame.verdict is None
    assert frame.evidence is not None
    assert "call path search skipped: token budget" in frame.evidence.notes[-1]


def test_cli_shows_verdicts_and_the_call_path(tmp_path: Path) -> None:
    project, analyzers = _setup(tmp_path)
    stack, _ = scripted_stack([], tmp_path / "model")
    proved = prove(project, [PILLOW], FINDINGS, analyzers, stack)
    result = ScanResult(source="shop", commit=None, packages=(PILLOW,), findings=proved)
    with cli.console.capture() as captured:
        cli._render(result, None)
    text = " ".join(captured.get().split())
    assert "Where each alert stands" in text
    assert "vulnerable module never loaded by your code │ 1" in text
    assert "Alert noise reduction: 25.0% (1 of 4 cleared with evidence); 1 proven reachable" in text

    out = tmp_path / "findings.json"
    out.write_text(json.dumps(payload(result)))
    assert json.loads(out.read_text())["summary"]["verdicts"]["path_certain"] == 1
    shown = CliRunner().invoke(cli.app, ["show", str(out), "GHSA-frame"], terminal_width=200)
    assert shown.exit_code == 0, shown.output
    assert "call path from your code (all hops certain)" in shown.output
    assert "shop.views.thumbnail  shop/views.py:11" in shown.output
    assert (
        "PIL.ImageFile.ImageFile.__init__  PIL/ImageFile.py:7 via pillow_open_registry"
        in shown.output
    )
