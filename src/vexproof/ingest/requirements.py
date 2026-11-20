"""Exact pins from a repository's requirements files, following `-r` includes.

Syft reads only files named `*requirements*.txt` and does not follow `-r`, so a project whose
`requirements.txt` says `-r requirements/base.txt` comes back with no packages. This reader
starts from the usual roots (`requirements.txt`, `requirements-*.txt`, `requirements_*.txt` and
every `.txt` under `requirements/`), follows `-r` and `--requirement` includes that stay inside
the repository, and keeps only exact pins (`name==1.2.3`): a range is not an installed version,
so it is counted as unpinned and reported, never guessed.

Not followed: `-c` constraint files (they limit versions, they install nothing), editable
installs, URLs and paths. Environment markers are evaluated for CPython 3 on Linux.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

ROOT_GLOBS = (
    "requirements.txt",
    "requirements-*.txt",
    "requirements_*.txt",
    "requirements/**/*.txt",
)
_INCLUDE = ("-r", "--requirement")
_ENVIRONMENT: dict[str, str] = {
    **{k: str(v) for k, v in default_environment().items()},
    "sys_platform": "linux",
    "platform_system": "Linux",
    "os_name": "posix",
    "implementation_name": "cpython",
    "platform_python_implementation": "CPython",
    "python_version": f"{sys.version_info[0]}.{sys.version_info[1]}",
}


@dataclass
class RequirementsRead:
    pins: dict[tuple[str, str], str] = field(default_factory=dict)  # (name, version) -> file
    unpinned: dict[str, str] = field(default_factory=dict)  # name -> file
    files: list[str] = field(default_factory=list)  # files read, relative to the repository

    @property
    def names(self) -> frozenset[str]:
        return frozenset({n for n, _ in self.pins} | set(self.unpinned))


def _logical_lines(text: str) -> list[str]:
    """Join backslash continuations and drop comments (pip needs whitespace before `#`)."""
    lines: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw if not raw.lstrip().startswith("#") else ""
        if " #" in line:
            line = line.split(" #", 1)[0]
        if line.rstrip().endswith("\\"):
            pending += line.rstrip()[:-1] + " "
            continue
        lines.append((pending + line).strip())
        pending = ""
    if pending.strip():
        lines.append(pending.strip())
    return [line for line in lines if line]


def _include(line: str) -> str | None:
    for flag in _INCLUDE:
        if line.startswith(flag + " ") or line.startswith(flag + "="):
            return line[len(flag) + 1 :].strip()
        if flag == "-r" and line.startswith("-r") and len(line) > 2:  # noqa: PLR2004
            return line[2:].strip()
    return None


def _pin(requirement: Requirement) -> str | None:
    specs = list(requirement.specifier)
    if len(specs) == 1 and specs[0].operator in {"==", "==="} and "*" not in specs[0].version:
        return specs[0].version
    return None


def read_requirements(repo: Path) -> RequirementsRead:
    root = repo.resolve()
    read = RequirementsRead()
    seen: set[Path] = set()

    def visit(path: Path) -> None:
        path = path.resolve()
        if path in seen or not path.is_file() or not path.is_relative_to(root):
            return
        seen.add(path)
        rel = str(path.relative_to(root))
        read.files.append(rel)
        for line in _logical_lines(path.read_text(encoding="utf-8", errors="replace")):
            target = _include(line)
            if target is not None:
                visit(path.parent / target)
                continue
            if line.startswith(("-", ".", "/")) or "://" in line or line.startswith("git+"):
                continue  # other options, editable installs, URLs and paths
            spec = line.split(" --", 1)[0].strip()  # per-requirement options such as --hash
            try:
                requirement = Requirement(spec)
            except InvalidRequirement:
                continue
            if requirement.url or (
                requirement.marker and not requirement.marker.evaluate(_ENVIRONMENT)
            ):
                continue
            name = str(canonicalize_name(requirement.name))
            version = _pin(requirement)
            if version is None:
                read.unpinned.setdefault(name, rel)
            else:
                read.pins.setdefault((name, version), rel)

    for pattern in ROOT_GLOBS:
        for path in sorted(repo.glob(pattern)):
            visit(path)
    # a name pinned in one file and unpinned in another is pinned
    pinned = {n for n, _ in read.pins}
    read.unpinned = {n: f for n, f in read.unpinned.items() if n not in pinned}
    return read
