"""Find the GitHub commits that fixed a vulnerability, from an OSV record.

Sources, in the order checked:
- references to `github.com/<owner>/<repo>/commit/<sha>`, including the
  `.../pull/<n>/commits/<sha>` form used by many GHSA records;
- `GIT` ranges whose repo is on GitHub, using their `fixed` events.

Pull-request links without a commit, mailing lists and release notes are ignored: they do not
identify the code change precisely. Those advisories fall to a lower evidence level later.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from vexproof.domain import FixCommit

_COMMIT_URL = re.compile(
    r"^https?://github\.com/(?P<owner>[A-Za-z0-9-]{1,39})/(?P<repo>[A-Za-z0-9._-]{1,100})/"
    r"(?:pull/\d+/)?commits?/(?P<sha>[0-9a-fA-F]{7,40})(?![0-9a-fA-F])"
)
_REPO_URL = re.compile(
    r"^https?://github\.com/(?P<owner>[A-Za-z0-9-]{1,39})/(?P<repo>[A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$"
)
_SHA = re.compile(r"^[0-9a-fA-F]{7,40}$")
MAX_FIX_COMMITS = 8


def fix_commits(record: Mapping[str, Any]) -> tuple[FixCommit, ...]:
    found: list[FixCommit] = []
    for ref in record.get("references") or []:
        match = _COMMIT_URL.match(str(ref.get("url", ""))) if isinstance(ref, dict) else None
        if match:
            found.append(_commit(match["owner"], match["repo"], match["sha"]))
    for affected in record.get("affected") or []:
        for rng in affected.get("ranges") or []:
            if rng.get("type") != "GIT":
                continue
            repo = _REPO_URL.match(str(rng.get("repo", "")))
            if not repo:
                continue
            for event in rng.get("events") or []:
                sha = str(event.get("fixed", ""))
                if _SHA.match(sha):
                    found.append(_commit(repo["owner"], repo["repo"], sha))
    unique: list[FixCommit] = []
    for commit in sorted(found, key=lambda c: -len(c.sha)):  # full SHAs first
        if not any(_same(commit, kept) for kept in unique):
            unique.append(commit)
    order = {id(c): i for i, c in enumerate(found)}
    unique.sort(key=lambda c: order[id(c)])
    return tuple(unique[:MAX_FIX_COMMITS])


def _same(short: FixCommit, full: FixCommit) -> bool:
    """Same repository (case-insensitive) and one SHA is a prefix of the other."""
    return (
        short.owner.lower() == full.owner.lower()
        and short.repo.lower() == full.repo.lower()
        and full.sha.startswith(short.sha)
    )


def _commit(owner: str, repo: str, sha: str) -> FixCommit:
    return FixCommit(owner=owner, repo=repo.removesuffix(".git"), sha=sha.lower())
