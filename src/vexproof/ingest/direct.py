"""Find a project's direct (declared) dependencies from its manifest files."""

from __future__ import annotations

import contextlib
import tomllib
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

_REQUIREMENTS_GLOBS = ("requirements.txt", "requirements/*.txt", "requirements-*.txt")


def _from_requirement_strings(lines: list[str]) -> set[str]:
    names: set[str] = set()
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http:", "https:", "file:")):
            continue
        try:
            names.add(str(canonicalize_name(Requirement(line).name)))
        except InvalidRequirement:
            continue
    return names


def _from_pyproject(data: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    project = data.get("project") or {}
    names |= _from_requirement_strings(list(project.get("dependencies") or []))
    for extra in (project.get("optional-dependencies") or {}).values():
        names |= _from_requirement_strings(list(extra))
    poetry = (data.get("tool") or {}).get("poetry") or {}
    for section in ("dependencies", "dev-dependencies"):
        names |= {str(canonicalize_name(n)) for n in (poetry.get(section) or {}) if n != "python"}
    for group in (poetry.get("group") or {}).values():
        names |= {str(canonicalize_name(n)) for n in (group.get("dependencies") or {})}
    return names


def direct_dependency_names(repo: Path) -> frozenset[str]:
    """Canonical names declared in pyproject.toml and top-level requirements files."""
    names: set[str] = set()
    pyproject = repo / "pyproject.toml"
    if pyproject.is_file():
        # A broken manifest only means fewer packages are marked direct.
        with contextlib.suppress(tomllib.TOMLDecodeError):
            names |= _from_pyproject(tomllib.loads(pyproject.read_text(encoding="utf-8")))
    for pattern in _REQUIREMENTS_GLOBS:
        for req_file in sorted(repo.glob(pattern)):
            names |= _from_requirement_strings(req_file.read_text(encoding="utf-8").splitlines())
    return frozenset(names)
