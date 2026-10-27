from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from vexproof.errors import IngestError
from vexproof.ingest import repo


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/pallets/flask", ("pallets", "flask")),
        ("https://github.com/pallets/flask.git", ("pallets", "flask")),
        ("https://github.com/a-b/c.d_e/", ("a-b", "c.d_e")),
    ],
)
def test_accepts_plain_github_urls(url: str, expected: tuple[str, str]) -> None:
    assert repo.parse_github_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/a/b",
        "https://gitlab.com/a/b",
        "https://github.com/a/b/tree/main",
        "file:///etc/passwd",
        "https://github.com.evil.com/a/b",
        "https://github.com/a/..",
        "--upload-pack=touch /tmp/x",
    ],
)
def test_rejects_anything_else(url: str) -> None:
    with pytest.raises(IngestError):
        repo.parse_github_url(url)


def test_rejects_non_sha_commit(tmp_path: Path) -> None:
    with pytest.raises(IngestError, match="hex SHA"):
        repo.checkout("https://github.com/a/b", "main; rm -rf /", tmp_path)


def test_checkout_runs_hardened_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        assert kwargs["check"] is True
        assert kwargs["timeout"]
        return subprocess.CompletedProcess(cmd, 0, stdout="abc1234def\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = repo.checkout("https://github.com/a/b", "abc1234", tmp_path)
    assert result.commit == "abc1234def"
    clone = calls[0]
    assert "protocol.file.allow=never" in clone
    assert "--no-recurse-submodules" in clone
    assert clone[-2] == "https://github.com/a/b.git"


def test_git_failure_becomes_ingest_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def failing(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.CalledProcessError(128, cmd, stderr="repository not found")

    monkeypatch.setattr(subprocess, "run", failing)
    with pytest.raises(IngestError, match="repository not found"):
        repo.checkout("https://github.com/a/b", "abc1234", tmp_path)
