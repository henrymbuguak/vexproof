"""Fetch fix commits with git: just the commit and its parent, never a full clone or checkout.

One bare repository per upstream project lives in the cache. Commits are fetched by SHA with
`--depth=2 --filter=blob:none`, so only commit and tree objects arrive up front; file contents
are fetched lazily, and only for the files a diff actually needs. No token or API is involved.

vexproof never asks git about an object it has not fetched: in a partial clone, git answers such
a question by silently downloading the object *with its whole history*. A small manifest of
fetched commits and their parents is the source of truth instead.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from vexproof.domain import FixCommit
from vexproof.gitcmd import GitError, run_git
from vexproof.sources.pypi import SourceError

_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_NO_REPO = re.compile(
    r"repository .*not found|could not read username|does not appear to be a git repository"
)
_NOT_FOUND = re.compile(r"not our ref|couldn't find remote ref|unadvertised object")
_MANIFEST = "vexproof-fetched.json"
_FETCH = ["fetch", "--quiet", "--no-tags", "--depth=2", "--filter=blob:none", "origin"]


class FixUnavailableError(SourceError):
    """A fix commit could not be fetched or read."""


@dataclass(frozen=True)
class FileChange:
    status: str  # A, M, D, R, C
    old_path: str | None  # path in the parent; None for added files
    new_path: str | None  # path in the fix; None for deleted files


@dataclass(frozen=True)
class CommitDiff:
    commit: FixCommit
    parent: str
    changes: tuple[FileChange, ...]
    python_patch: str  # `git diff -U0` of .py files only


class GitFixFetcher:
    def __init__(
        self,
        cache_dir: Path,
        *,
        url_template: str = "https://github.com/{owner}/{repo}.git",
        allow_file_protocol: bool = False,
        timeout_s: float = 180,
    ) -> None:
        self._dir = cache_dir / "git"
        self._url = url_template
        self._allow_file = allow_file_protocol
        self._timeout = timeout_s
        self._locks: dict[Path, threading.Lock] = {}
        self._guard = threading.Lock()

    # -- plumbing -----------------------------------------------------------------------------

    def _git(self, args: list[str], repo: Path) -> str:
        return run_git(
            ["-C", str(repo), *args], timeout_s=self._timeout, allow_file_protocol=self._allow_file
        )

    def _repo(self, commit: FixCommit) -> tuple[Path, threading.Lock]:
        if not (_NAME.match(commit.owner) and _NAME.match(commit.repo)):
            raise FixUnavailableError(f"invalid repository name {commit.owner}/{commit.repo}")
        path = self._dir / f"{commit.owner.lower()}__{commit.repo.lower()}.git"
        with self._guard:
            lock = self._locks.setdefault(path, threading.Lock())
        return path, lock

    def _init(self, repo: Path, commit: FixCommit) -> None:
        if (repo / "HEAD").is_file():
            return
        repo.parent.mkdir(parents=True, exist_ok=True)
        run_git(["init", "--bare", "--quiet", str(repo)], allow_file_protocol=self._allow_file)
        settings = {
            "core.repositoryformatversion": "1",
            "extensions.partialClone": "origin",
            "remote.origin.url": self._url.format(owner=commit.owner, repo=commit.repo),
            "remote.origin.promisor": "true",
            "remote.origin.partialclonefilter": "blob:none",
        }
        for key, value in settings.items():
            self._git(["config", key, value], repo)

    @staticmethod
    def _manifest(repo: Path) -> dict[str, str]:
        """{fetched commit sha: parent sha}."""
        path = repo / _MANIFEST
        return dict(json.loads(path.read_text(encoding="utf-8"))) if path.is_file() else {}

    def _record(self, repo: Path, shas: Iterable[str]) -> None:
        manifest = self._manifest(repo)
        for sha in shas:
            try:  # safe: the commit was just fetched, so git does not need to download anything
                manifest[sha] = self._git(["rev-parse", f"{sha}^1"], repo)
            except GitError:
                continue  # a root commit has no parent to diff against
        (repo / _MANIFEST).write_text(json.dumps(manifest, indent=1, sort_keys=True))

    def _fetch(self, repo: Path, shas: list[str]) -> dict[str, str]:
        """Fetch `shas` in one round trip; on failure retry one by one. Returns {sha: reason}."""
        try:
            self._git([*_FETCH, *shas], repo)
        except GitError as exc:
            if len(shas) == 1:
                return {shas[0]: _reason(str(exc))}
            errors: dict[str, str] = {}
            for sha in shas:  # one bad SHA fails the whole batch; retry the rest individually
                try:
                    self._git([*_FETCH, sha], repo)
                except GitError as single:
                    errors[sha] = _reason(str(single))
            return errors
        return {}

    # -- public API ---------------------------------------------------------------------------

    def prefetch(self, commits: Iterable[FixCommit]) -> dict[str, str]:
        """Fetch commits in as few round trips as possible. Returns {sha: reason} for failures."""
        failures: dict[str, str] = {}
        by_repo: dict[Path, list[FixCommit]] = {}
        for commit in commits:
            if not _FULL_SHA.match(commit.sha):
                failures[commit.sha] = "abbreviated commit id; git needs the full SHA"
                continue
            try:
                repo, _ = self._repo(commit)
            except FixUnavailableError as exc:
                failures[commit.sha] = str(exc)
                continue
            by_repo.setdefault(repo, []).append(commit)
        for repo, group in by_repo.items():
            _, lock = self._repo(group[0])
            with lock:
                try:
                    self._init(repo, group[0])
                    missing = sorted({c.sha for c in group} - self._manifest(repo).keys())
                    errors = self._fetch(repo, missing) if missing else {}
                    self._record(repo, [s for s in missing if s not in errors])
                except GitError as exc:
                    failures.update({c.sha: _reason(str(exc)) for c in group})
                    continue
                known = self._manifest(repo)
                for commit in group:
                    if commit.sha not in known:
                        failures[commit.sha] = errors.get(commit.sha, "commit has no parent")
        return failures

    def diff(self, commit: FixCommit) -> CommitDiff:
        failures = self.prefetch([commit])
        if commit.sha in failures:
            raise FixUnavailableError(failures[commit.sha])
        repo, lock = self._repo(commit)
        base = ["diff", "--no-color", "--no-ext-diff", "-M"]
        with lock:
            parent = self._manifest(repo)[commit.sha]
            try:
                status = self._git([*base, "--name-status", "-z", parent, commit.sha], repo)
                patch = self._git([*base, "-U0", parent, commit.sha, "--", "*.py"], repo)
            except GitError as exc:
                raise FixUnavailableError(_reason(str(exc))) from exc
        return CommitDiff(commit, parent, _parse_status(status), patch)

    def read(self, commit: FixCommit, rev: str, path: str) -> str | None:
        """File contents at `rev`, which must be a fetched commit or the parent of one."""
        repo, lock = self._repo(commit)
        with lock:
            manifest = self._manifest(repo)
            if rev not in manifest and rev not in manifest.values():
                return None
            try:
                return self._git(["show", f"{rev}:{path}"], repo) + "\n"
            except GitError:
                return None


def _parse_status(raw: str) -> tuple[FileChange, ...]:
    fields = raw.split("\0")
    changes: list[FileChange] = []
    i = 0
    while i < len(fields) and fields[i]:
        status = fields[i][0]
        if status in {"R", "C"}:
            changes.append(FileChange(status, fields[i + 1], fields[i + 2]))
            i += 3
            continue
        path = fields[i + 1]
        changes.append(
            FileChange(status, None if status == "A" else path, None if status == "D" else path)
        )
        i += 2
    return tuple(changes)


def _reason(message: str) -> str:
    lowered = message.lower()
    if _NOT_FOUND.search(lowered):
        return "commit not found in the repository"
    if _NO_REPO.search(lowered):
        return "repository not found or not public"
    return message.splitlines()[0][:200] if message else "git failed"
