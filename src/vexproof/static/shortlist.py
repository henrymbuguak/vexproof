"""Shortlist the functions a fix commit changed, and check they exist in the installed version.

For every fix commit: diff it against its parent, map each changed `.py` file to a module of the
installed package, and map each changed line to the function containing it in the *pre-fix*
code. A candidate survives only if a function of that name exists in the installed version.

The evidence level that results:
- L1: at least one changed function exists in the installed code (candidates for Chapter 3);
- L2: changed modules exist, but no changed function does (module-level changes only);
- L3: nothing usable (no fix commit, fetch failure, non-Python fix, or code absent).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Protocol

from unidiff.patch import PatchSet

from vexproof.domain import Advisory, Candidate, FixCommit, Level
from vexproof.sources.git import CommitDiff, FixUnavailableError
from vexproof.sources.tree import SourceTree
from vexproof.static.functions import FunctionSpan, enclosing, function_spans

MAX_COMMITS = 6
MAX_SNIPPET_LINES = 60
_DOC_SUFFIXES = frozenset({".rst", ".md", ".txt", ".toml", ".cfg", ".ini", ".yml", ".yaml", ""})


class FixSource(Protocol):
    def diff(self, commit: FixCommit) -> CommitDiff: ...
    def read(self, commit: FixCommit, rev: str, path: str) -> str | None: ...


@dataclass
class Shortlist:
    level: Level
    candidates: tuple[Candidate, ...] = ()
    changed_modules: tuple[str, ...] = ()
    fix_commits: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


@dataclass
class _Acc:
    lines: dict[str, int] = field(default_factory=dict)  # qualname -> changed lines
    commits: dict[str, set[str]] = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)
    modules_changed: set[str] = field(default_factory=set)  # installed modules touched
    modules_absent: set[str] = field(default_factory=set)
    absent_functions: set[str] = field(default_factory=set)
    hunks: dict[str, list[str]] = field(default_factory=dict)
    snippet_commit: dict[str, str] = field(default_factory=dict)
    native_paths: set[str] = field(default_factory=set)
    unmapped: bool = False
    notes: list[str] = field(default_factory=list)


def _is_test_module(module: str, rel: str) -> bool:
    parts = module.split(".")
    name = PurePosixPath(rel).name
    return any(p in {"tests", "test", "testing"} for p in parts) or name.startswith("test_")


def _is_test_or_tooling(path: str) -> bool:
    parts = PurePosixPath(path).parts
    name = parts[-1]
    return (
        any(
            p in {"tests", "test", "testing", "docs", "doc", "examples", "scripts", "Tests"}
            for p in parts[:-1]
        )
        or name.startswith("test_")
        or name in {"setup.py", "conftest.py", "noxfile.py", "tasks.py"}
    )


def _module_guess(path: str) -> str:
    """Best-effort dotted name for a repository file that the installed package lacks."""
    parts = list(PurePosixPath(path).with_suffix("").parts)
    if parts and parts[0] in {"src", "lib"}:
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def map_path(repo_path: str, tree: SourceTree) -> tuple[str, str] | None:
    """Repository file path -> (module, installed relative path), by longest path suffix.

    Handles layouts such as `src/PIL/Image.py` in the repo vs `PIL/Image.py` in the wheel.
    """
    best: tuple[str, str] | None = None
    for rel, module in tree.python_files().items():
        if (repo_path == rel or repo_path.endswith("/" + rel)) and (
            best is None or len(rel) > len(best[1])
        ):
            best = (module, rel)
    return best


def _touched(patched_file: object) -> list[tuple[int, int | None, str]]:
    """(pre-fix line, indent of inserted code or None, hunk text) for every changed spot."""
    spots: list[tuple[int, int | None, str]] = []
    for hunk in patched_file:  # type: ignore[attr-defined]
        text = str(hunk)
        removed = [ln.source_line_no for ln in hunk if ln.is_removed and ln.source_line_no]
        spots += [(n, None, text) for n in removed]
        if not removed:  # pure insertion after line `source_start`
            added = [ln.value for ln in hunk if ln.is_added and ln.value.strip()]
            indent = len(added[0]) - len(added[0].lstrip()) if added else None
            spots.append((max(hunk.source_start, 1), indent, text))
    return spots


def _snippet(hunks: list[str]) -> str:
    """The fix's diff for one function, capped so prompts stay small."""
    lines: list[str] = []
    for hunk in hunks:
        lines += hunk.rstrip("\n").splitlines()
        if len(lines) >= MAX_SNIPPET_LINES:
            return "\n".join([*lines[:MAX_SNIPPET_LINES], "... (diff truncated)"])
    return "\n".join(lines)


def _apply_commit(diff: CommitDiff, tree: SourceTree, fetcher: FixSource, acc: _Acc) -> None:
    sha = diff.commit.sha[:12]
    code = [
        path
        for change in diff.changes
        if (path := change.old_path or change.new_path) and not _is_test_or_tooling(path)
    ]
    native = [
        p for p in code if not p.endswith(".py") and PurePosixPath(p).suffix not in _DOC_SUFFIXES
    ]
    if native and not any(p.endswith(".py") for p in code):
        acc.native_paths.update(native)
    for patched in PatchSet(diff.python_patch):
        if patched.is_added_file:
            continue  # a module created by the fix did not exist in vulnerable versions
        old_path = patched.source_file.removeprefix("a/")
        mapped = map_path(old_path, tree)
        if mapped is None:
            acc.unmapped = True
            if old_path.endswith(".py") and not _is_test_or_tooling(old_path):
                acc.modules_absent.add(_module_guess(old_path))
            continue
        module, rel = mapped
        if _is_test_module(module, rel):
            continue
        acc.modules_changed.add(module)
        pre_fix = fetcher.read(diff.commit, diff.parent, old_path)
        spans = function_spans(pre_fix) if pre_fix else []
        installed_text = tree.source(module) or ""
        installed = {s.qualname for s in function_spans(installed_text)}
        for line, indent, hunk in _touched(patched):
            span: FunctionSpan | None = enclosing(spans, line, indent)
            if span is None:
                continue  # module-level code: counts toward the module only
            qualname = f"{module}.{span.qualname}"
            if span.qualname not in installed:
                acc.absent_functions.add(qualname)
                continue
            acc.lines[qualname] = acc.lines.get(qualname, 0) + 1
            acc.commits.setdefault(qualname, set()).add(sha)
            acc.files[qualname] = rel
            # One commit's view of the change is enough; backports repeat the same hunks.
            first = acc.snippet_commit.setdefault(qualname, sha)
            hunks = acc.hunks.setdefault(qualname, [])
            if first == sha and hunk not in hunks:
                hunks.append(hunk)


def build_shortlist(advisory: Advisory, tree: SourceTree, fetcher: FixSource) -> Shortlist:
    commits = advisory.fix_commits[:MAX_COMMITS]
    if not commits:
        return Shortlist(Level.L3_NONE, notes=("the advisory names no fix commit",))
    acc = _Acc()
    used: list[str] = []
    for commit in commits:
        try:
            diff = fetcher.diff(commit)
        except FixUnavailableError as exc:
            acc.notes.append(f"{commit.url}: {exc}")
            continue
        used.append(commit.url)
        _apply_commit(diff, tree, fetcher, acc)
    candidates = tuple(
        Candidate(
            qualname=q,
            module=tree.python_files()[acc.files[q]],
            file=acc.files[q],
            changed_lines=acc.lines[q],
            commits=tuple(sorted(acc.commits[q])),
            diff=_snippet(acc.hunks.get(q, [])),
        )
        for q in sorted(acc.lines, key=lambda q: (-acc.lines[q], q))
    )
    notes = list(acc.notes)
    if not used:
        return Shortlist(
            Level.L3_NONE, fix_commits=(), notes=(*notes, "no fix commit could be read")
        )
    if acc.modules_absent:
        shown = ", ".join(sorted(acc.modules_absent)[:5])
        notes.append(f"the fix also changes code that is not in the installed package: {shown}")
    if acc.absent_functions:
        shown = ", ".join(sorted(acc.absent_functions)[:5])
        notes.append(f"changed functions not present in installed version: {shown}")
    if candidates:
        level = Level.L1_SYMBOL
    elif acc.modules_changed:
        level = Level.L2_MODULE
        notes.append(
            "the fix changes module-level code only, or functions absent from this version"
        )
    else:
        level = Level.L3_NONE
        if acc.native_paths:
            shown = ", ".join(sorted(acc.native_paths)[:3])
            notes.append(f"the fix changes only non-Python code (compiled or bundled): {shown}")
        elif not acc.modules_absent:
            notes.append("no change in the fix maps to the installed package's code")
    return Shortlist(
        level=level,
        candidates=candidates,
        changed_modules=tuple(sorted(acc.modules_changed)),
        fix_commits=tuple(used),
        notes=tuple(notes),
    )


def shortlist_level_counts(shortlists: Mapping[str, Shortlist]) -> dict[Level, int]:
    counts: dict[Level, int] = {}
    for shortlist in shortlists.values():
        counts[shortlist.level] = counts.get(shortlist.level, 0) + 1
    return counts
