"""Clone a public GitHub repository at a pinned commit, safely.

Safety rules: only https://github.com/<owner>/<repo> URLs; no submodules; plus the protections
in `vexproof.gitcmd` (no hooks, no local-file protocol, no prompts, argument lists, timeouts).
The target's code is checked out as data and never executed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from vexproof.errors import IngestError
from vexproof.gitcmd import GitError, run_git

_GITHUB_URL = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9-]{1,39})/(?P<repo>[A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$"
)
_COMMIT = re.compile(r"^[0-9a-f]{7,40}$")


@dataclass(frozen=True, slots=True)
class Checkout:
    path: Path
    url: str
    commit: str


def parse_github_url(url: str) -> tuple[str, str]:
    """Return (owner, repo) or raise IngestError for anything but a plain GitHub repo URL."""
    match = _GITHUB_URL.match(url)
    if not match or match["repo"] in {".", ".."}:
        raise IngestError(f"only https://github.com/<owner>/<repo> URLs are accepted, got {url!r}")
    return match["owner"], match["repo"]


def _git(args: list[str], cwd: Path | None = None) -> str:
    try:
        return run_git(args, cwd)
    except GitError as exc:
        raise IngestError(str(exc)) from exc


def checkout(url: str, commit: str, workspace: Path) -> Checkout:
    """Clone `url` into `workspace/<owner>__<repo>` and check out `commit` (detached)."""
    owner, repo = parse_github_url(url)
    if not _COMMIT.match(commit):
        raise IngestError(f"commit must be a hex SHA (7-40 chars), got {commit!r}")
    dest = workspace / f"{owner}__{repo}"
    if not (dest / ".git").is_dir():
        workspace.mkdir(parents=True, exist_ok=True)
        clean_url = f"https://github.com/{owner}/{repo}.git"
        _git(
            [
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                "--no-recurse-submodules",
                clean_url,
                str(dest),
            ]
        )
    _git(["checkout", "--detach", "--quiet", commit], cwd=dest)
    resolved = _git(["rev-parse", "HEAD"], cwd=dest)
    return Checkout(path=dest.resolve(), url=url, commit=resolved)
