from __future__ import annotations

from vexproof.domain import FixCommit
from vexproof.intel.fixrefs import MAX_FIX_COMMITS, fix_commits

SHA = "0123456789abcdef0123456789abcdef01234567"


def _refs(*urls: str) -> dict[str, object]:
    return {"references": [{"type": "FIX", "url": u} for u in urls]}


def test_commit_url_forms_seen_in_real_ghsa_records() -> None:
    record = _refs(
        f"https://github.com/django/django/commit/{SHA}",
        # GHSA-g6rj-rv7j-xwp4 links a commit inside a pull request
        f"https://github.com/python-pillow/Pillow/pull/5377/commits/{SHA[:-1]}e",
        f"https://github.com/owner/repo/commit/{SHA.upper()[:12]}.patch",
        f"https://github.com/owner/repo/commit/{SHA}#diff-abc",
    )
    assert [c.url for c in fix_commits(record)] == [
        f"https://github.com/django/django/commit/{SHA}",
        f"https://github.com/python-pillow/Pillow/commit/{SHA[:-1]}e",
        # the short SHA and the full SHA name the same commit: the full one is kept
        f"https://github.com/owner/repo/commit/{SHA}",
    ]


def test_ignores_non_commit_links() -> None:
    record = _refs(
        "https://github.com/python-pillow/Pillow/pull/5377",
        "https://github.com/django/django",
        "https://www.djangoproject.com/weblog/2025/jun/04/security-releases",
        "https://gitlab.com/owner/repo/-/commit/" + SHA,
        "https://github.com/owner/repo/commit/not-a-sha",
    )
    assert fix_commits(record) == ()


def test_git_range_fixed_events_on_github() -> None:
    record = {
        "affected": [
            {
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/example/examplelib.git",
                        "events": [{"introduced": "0"}, {"fixed": SHA}],
                    },
                    {
                        "type": "GIT",
                        "repo": "https://example.org/x.git",
                        "events": [{"fixed": SHA}],
                    },
                    {"type": "ECOSYSTEM", "events": [{"fixed": "1.0"}]},
                ]
            }
        ]
    }
    assert fix_commits(record) == (FixCommit(owner="example", repo="examplelib", sha=SHA),)


def test_duplicates_merged_case_insensitively_and_capped() -> None:
    urls = [
        f"https://github.com/Django/Django/commit/{SHA}",
        f"https://github.com/django/django/commit/{SHA}",
    ]
    urls += [f"https://github.com/o/r/commit/{i:040x}" for i in range(20)]
    commits = fix_commits(_refs(*urls))
    assert len(commits) == MAX_FIX_COMMITS
    assert commits[0].owner == "Django"
