from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.gitrepo import Upstream, make_upstream
from vexproof.domain import FixCommit
from vexproof.sources.git import (
    FileChange,
    FixUnavailableError,
    GitFixFetcher,
    _parse_status,
    _reason,
)


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


def test_diff_fetches_only_the_commit_and_reads_prefix_files(
    upstream: Upstream, fetcher: GitFixFetcher, tmp_path: Path
) -> None:
    commit = FixCommit(owner="example", repo="examplelib", sha=upstream.fix)
    diff = fetcher.diff(commit)
    assert diff.parent == upstream.vulnerable
    assert set(diff.changes) == {
        FileChange("M", "src/examplelib/parser.py", "src/examplelib/parser.py"),
        FileChange("A", None, "src/examplelib/new_module.py"),
        FileChange("M", "tests/test_parser.py", "tests/test_parser.py"),
    }
    assert "+    return ast.literal_eval(data)" in diff.python_patch
    assert "_speedups.c" not in diff.python_patch
    prefix = fetcher.read(commit, diff.parent, "src/examplelib/parser.py")
    assert prefix is not None
    assert "eval(data)" in prefix
    assert fetcher.read(commit, diff.parent, "missing.py") is None
    assert not (tmp_path / "cache/git/example__examplelib.git/worktrees").exists()


def test_fetch_is_shallow(upstream: Upstream, fetcher: GitFixFetcher, tmp_path: Path) -> None:
    latest = FixCommit(owner="example", repo="examplelib", sha=upstream.native_fix)
    assert fetcher.diff(latest).parent == upstream.fix
    repo = tmp_path / "cache/git/example__examplelib.git"
    assert (repo / "shallow").read_text().strip() == upstream.fix  # history stops at the parent
    # never-fetched commits are not read, so git never lazily downloads history
    assert fetcher.read(latest, upstream.vulnerable, "src/examplelib/parser.py") is None
    objects = subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "rev-list", "--all", "--objects", "--exclude-promisor-objects"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    assert upstream.vulnerable not in objects


def test_prefetch_batches_and_reports_failures(upstream: Upstream, fetcher: GitFixFetcher) -> None:
    good = FixCommit(owner="example", repo="examplelib", sha=upstream.fix)
    missing = FixCommit(owner="example", repo="examplelib", sha="f" * 40)
    short = FixCommit(owner="example", repo="examplelib", sha=upstream.fix[:10])
    no_repo = FixCommit(owner="nobody", repo="nothing", sha="a" * 40)
    failures = fetcher.prefetch([good, missing, short, no_repo])
    assert set(failures) == {missing.sha, short.sha, no_repo.sha}
    assert "full SHA" in failures[short.sha]
    with pytest.raises(FixUnavailableError):
        fetcher.diff(missing)
    assert fetcher.prefetch([good]) == {}  # already present: no refetch needed


def test_invalid_repo_names_rejected(fetcher: GitFixFetcher) -> None:
    with pytest.raises(FixUnavailableError, match="invalid repository"):
        fetcher.diff(FixCommit(owner="a/b", repo="c", sha="a" * 40))


def test_status_parsing_and_reasons() -> None:
    raw = "M\0a.py\0R087\0old.py\0new.py\0A\0b.py\0D\0c.py\0"
    assert _parse_status(raw) == (
        FileChange("M", "a.py", "a.py"),
        FileChange("R", "old.py", "new.py"),
        FileChange("A", None, "b.py"),
        FileChange("D", "c.py", None),
    )
    assert (
        _reason("fatal: remote error: upload-pack: not our ref abc")
        == "commit not found in the repository"
    )
    assert _reason("fatal: repository 'x' not found") == "repository not found or not public"
    assert _reason("") == "git failed"
