"""The analyze stage end to end: mocked PyPI, a real local git repository, a real project tree."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from tests.gitrepo import VULNERABLE, Upstream, make_upstream
from tests.wheels import make_wheel, sha256
from vexproof.cli import app
from vexproof.domain import Advisory, Finding, FixCommit, Level, Package, Verdict
from vexproof.intel.http import JsonHttp
from vexproof.pipeline import Analyzers, ScanResult, analyze, level_counts
from vexproof.sources.git import GitFixFetcher
from vexproof.sources.pypi import PyPIClient
from vexproof.sources.store import SourceStore

PYPI = "https://pypi.test"
EXAMPLE = Package(name="examplelib", version="1.0", direct=True)
UNUSED = Package(name="unusedlib", version="2.0")
TESTONLY = Package(name="testhelper", version="0.1")
GHOST = Package(name="ghostlib", version="9.9")


def _serve(router: respx.MockRouter, tmp: Path, package: Package, files: dict[str, str]) -> None:
    filename = f"{package.name}-{package.version}-py3-none-any.whl"
    data = make_wheel(tmp / filename, package.name, package.version, files)
    release = {
        "filename": filename,
        "packagetype": "bdist_wheel",
        "size": len(data),
        "url": f"https://files.test/{filename}",
        "digests": {"sha256": sha256(data)},
    }
    router.get(f"{PYPI}/pypi/{package.name}/{package.version}/json").respond(
        json={"urls": [release]}
    )
    router.get(f"https://files.test/{filename}").respond(content=data)


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "app").mkdir(parents=True)
    (root / "app/__init__.py").write_text("")
    (root / "app/views.py").write_text(
        "from examplelib.parser import load\n\ndef view(b):\n    return load(b)\n"
    )
    (root / "app/tests.py").write_text("import testhelper\n")
    return root


@pytest.fixture
def upstream(tmp_path: Path) -> Upstream:
    return make_upstream(tmp_path / "remote")


@pytest.fixture
def analyzers(tmp_path: Path, http: JsonHttp) -> Iterator[Analyzers]:
    with respx.mock(assert_all_called=False) as router, httpx.Client() as client:
        _serve(
            router,
            tmp_path,
            EXAMPLE,
            {"examplelib/__init__.py": "", "examplelib/parser.py": VULNERABLE},
        )
        _serve(router, tmp_path, UNUSED, {"unusedlib/__init__.py": ""})
        _serve(router, tmp_path, TESTONLY, {"testhelper/__init__.py": ""})
        router.get(f"{PYPI}/pypi/{GHOST.name}/{GHOST.version}/json").respond(404)
        yield Analyzers(
            store=SourceStore(tmp_path / "cache", PyPIClient(http, client, PYPI, 10**7)),
            fetcher=GitFixFetcher(
                tmp_path / "cache",
                url_template=f"file://{tmp_path}/remote/{{owner}}__{{repo}}",
                allow_file_protocol=True,
            ),
            workers=4,
        )


def _finding(package: Package, advisory_id: str, *shas: str) -> Finding:
    commits = tuple(FixCommit(owner="example", repo="examplelib", sha=s) for s in shas)
    return Finding(
        id=f"{advisory_id}:{package.name}@{package.version}",
        package=package,
        advisory=Advisory(id=advisory_id, summary=f"{advisory_id} summary", fix_commits=commits),
    )


def test_analyze_assigns_every_level(
    project: Path, upstream: Upstream, analyzers: Analyzers
) -> None:
    findings = [
        _finding(EXAMPLE, "GHSA-python-fix", upstream.fix),
        _finding(EXAMPLE, "GHSA-native-fix", upstream.native_fix),
        _finding(UNUSED, "GHSA-unused"),
        _finding(TESTONLY, "GHSA-testonly"),
        _finding(GHOST, "GHSA-ghost"),
    ]
    result = {
        f.advisory.id: f
        for f in analyze(project, [EXAMPLE, UNUSED, TESTONLY, GHOST], findings, analyzers)
    }

    python_fix = result["GHSA-python-fix"]
    assert python_fix.evidence is not None
    assert python_fix.evidence.level is Level.L1_SYMBOL
    assert [c.qualname for c in python_fix.evidence.candidates] == [
        "examplelib.parser.Parser.feed",
        "examplelib.parser.load",
    ]
    assert python_fix.verdict is None  # function-level verdicts come in later chapters
    assert "imported by production code" in python_fix.evidence.notes[0]

    assert result["GHSA-native-fix"].evidence.level is Level.L3_NONE  # type: ignore[union-attr]

    unused = result["GHSA-unused"]
    assert unused.verdict is Verdict.NOT_AFFECTED
    assert unused.justification == "vulnerable_code_not_in_execute_path"
    assert unused.evidence.level is Level.L0_NOT_IMPORTED  # type: ignore[union-attr]

    test_only = result["GHSA-testonly"]
    assert test_only.verdict is Verdict.NOT_AFFECTED
    assert "imported_only_by_tests" in test_only.evidence.checks_passed  # type: ignore[union-attr]

    ghost = result["GHSA-ghost"]
    assert ghost.verdict is None
    assert ghost.evidence.level is Level.L3_NONE  # type: ignore[union-attr]
    assert "not found on PyPI" in " ".join(ghost.evidence.notes)  # type: ignore[union-attr]

    assert level_counts(list(result.values())) == {"L0": 2, "L1": 1, "L2": 0, "L3": 2}


def test_show_command_explains_one_alert(
    project: Path, upstream: Upstream, analyzers: Analyzers, tmp_path: Path
) -> None:
    from vexproof.service import payload

    findings = analyze(
        project, [EXAMPLE], [_finding(EXAMPLE, "GHSA-python-fix", upstream.fix)], analyzers
    )
    out = tmp_path / "findings.json"
    result = ScanResult(source="project", commit=None, packages=(EXAMPLE,), findings=findings)
    out.write_text(json.dumps(payload(result)))
    runner = CliRunner()
    shown = runner.invoke(app, ["show", str(out), "ghsa-python-fix"], terminal_width=200)
    assert shown.exit_code == 0, shown.output
    assert "evidence level: L1" in shown.output
    assert "candidate: examplelib.parser.Parser.feed" in shown.output
    assert (
        f"fix commit: https://github.com/example/examplelib/commit/{upstream.fix}" in shown.output
    )
    assert runner.invoke(app, ["show", str(out), "GHSA-nope"]).exit_code == 1
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert runner.invoke(app, ["show", str(bad), "x"]).exit_code == 2
