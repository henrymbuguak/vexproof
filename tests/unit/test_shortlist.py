from __future__ import annotations

from pathlib import Path

import pytest

from tests.gitrepo import VULNERABLE, Upstream, make_upstream
from tests.trees import make_tree
from vexproof.domain import Advisory, FixCommit, Level, Package
from vexproof.sources.git import GitFixFetcher
from vexproof.sources.tree import SourceTree
from vexproof.static.shortlist import _module_guess, build_shortlist, map_path

PKG = Package(name="examplelib", version="1.0")


@pytest.fixture
def upstream(tmp_path: Path) -> Upstream:
    return make_upstream(tmp_path / "remote")


@pytest.fixture
def fetcher(tmp_path: Path) -> GitFixFetcher:
    return GitFixFetcher(
        tmp_path / "cache",
        url_template=f"file://{tmp_path}/remote/{{owner}}__{{repo}}",
        allow_file_protocol=True,
    )


@pytest.fixture
def installed(tmp_path: Path) -> SourceTree:
    """The vulnerable release as installed: same code, wheel layout (no src/)."""
    return make_tree(
        tmp_path / "trees",
        PKG,
        {"examplelib/__init__.py": "", "examplelib/parser.py": VULNERABLE},
    )


def _advisory(*shas: str) -> Advisory:
    return Advisory(
        id="GHSA-x",
        fix_commits=tuple(FixCommit(owner="example", repo="examplelib", sha=s) for s in shas),
    )


def test_map_path_uses_longest_suffix(installed: SourceTree) -> None:
    assert map_path("src/examplelib/parser.py", installed) == (
        "examplelib.parser",
        "examplelib/parser.py",
    )
    assert map_path("examplelib/parser.py", installed) == (
        "examplelib.parser",
        "examplelib/parser.py",
    )
    assert map_path("other/examplelib_parser.py", installed) is None


def test_python_fix_gives_l1_candidates(
    upstream: Upstream, fetcher: GitFixFetcher, installed: SourceTree
) -> None:
    result = build_shortlist(_advisory(upstream.fix), installed, fetcher)
    assert result.level is Level.L1_SYMBOL
    names = [c.qualname for c in result.candidates]
    assert names == ["examplelib.parser.Parser.feed", "examplelib.parser.load"]
    assert result.candidates[0].changed_lines == 1  # pure insertion inside feed
    assert result.candidates[0].file == "examplelib/parser.py"
    feed_diff = result.candidates[0].diff
    assert feed_diff.startswith("@@ ")
    assert '+            raise ValueError("chunk too large")' in feed_diff
    assert "-    return eval(data)" in result.candidates[1].diff
    assert result.changed_modules == ("examplelib.parser",)
    assert result.fix_commits == (f"https://github.com/example/examplelib/commit/{upstream.fix}",)
    assert not any(
        "not in the installed package" in n for n in result.notes
    )  # tests and new files ignored


def test_native_only_fix_gives_l3_with_paths(
    upstream: Upstream, fetcher: GitFixFetcher, installed: SourceTree
) -> None:
    result = build_shortlist(_advisory(upstream.native_fix), installed, fetcher)
    assert result.level is Level.L3_NONE
    assert result.notes == (
        "the fix changes only non-Python code (compiled or bundled): src/examplelib/_speedups.c",
    )


def test_functions_absent_from_installed_version(
    upstream: Upstream, fetcher: GitFixFetcher, tmp_path: Path
) -> None:
    older = make_tree(tmp_path / "older", PKG, {"examplelib/parser.py": "VERSION = '0.9'\n"})
    result = build_shortlist(_advisory(upstream.fix), older, fetcher)
    assert result.level is Level.L2_MODULE
    assert "examplelib.parser.load" in " ".join(result.notes)


def test_module_absent_from_installed_package(
    upstream: Upstream, fetcher: GitFixFetcher, tmp_path: Path
) -> None:
    unrelated = make_tree(tmp_path / "unrelated", PKG, {"otherpkg/__init__.py": ""})
    result = build_shortlist(_advisory(upstream.fix), unrelated, fetcher)
    assert result.level is Level.L3_NONE
    assert result.notes == (
        "the fix also changes code that is not in the installed package: examplelib.parser",
    )


def test_no_commits_or_unreadable_commits(fetcher: GitFixFetcher, installed: SourceTree) -> None:
    assert build_shortlist(Advisory(id="GHSA-x"), installed, fetcher).notes == (
        "the advisory names no fix commit",
    )
    result = build_shortlist(_advisory("e" * 40), installed, fetcher)
    assert result.level is Level.L3_NONE
    assert result.notes[-1] == "no fix commit could be read"


@pytest.mark.parametrize(
    ("path", "module"),
    [
        ("src/PIL/BlpImagePlugin.py", "PIL.BlpImagePlugin"),
        ("pkg/__init__.py", "pkg"),
        ("lib/a/b.py", "a.b"),
    ],
)
def test_module_guess(path: str, module: str) -> None:
    assert _module_guess(path) == module


def test_snippet_is_capped() -> None:
    from vexproof.static.shortlist import MAX_SNIPPET_LINES, _snippet

    hunks = ["@@ -1 +1 @@\n" + "\n".join(f"-{i}" for i in range(100))]
    lines = _snippet(hunks).splitlines()
    assert len(lines) == MAX_SNIPPET_LINES + 1
    assert lines[-1] == "... (diff truncated)"
