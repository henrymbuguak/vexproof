"""Scan the analysed project's own code: production and test code are kept apart."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from vexproof.sources.tree import module_name
from vexproof.static.imports import ModuleImports, scan_source

SKIP_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", ".venv", "venv", "env", ".env", "node_modules", "build", "dist",
        "site-packages", "__pycache__", ".tox", ".nox", ".eggs", ".mypy_cache", ".pytest_cache",
        ".ruff_cache", ".vexproof-cache",
    }
)  # fmt: skip
_TEST_DIRS = frozenset({"tests", "test", "testing"})
MAX_FILE_BYTES = 2_000_000


def is_test_path(rel: PurePosixPath) -> bool:
    name = rel.name
    return (
        any(part in _TEST_DIRS for part in rel.parts[:-1])
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name in {"conftest.py", "tests.py", "test.py"}  # Django keeps tests in app/tests.py
    )


@dataclass
class ProjectScan:
    production: ModuleImports = field(default_factory=ModuleImports)
    tests: ModuleImports = field(default_factory=ModuleImports)
    local_modules: set[str] = field(default_factory=set)
    files: int = 0
    unparsed_files: list[str] = field(default_factory=list)
    computed_dynamic_imports: list[str] = field(default_factory=list)  # "path:line"


def python_files(root: Path) -> list[PurePosixPath]:
    found: list[PurePosixPath] = []
    for current, dirs, files in os.walk(root):
        here = Path(current)
        dirs[:] = sorted(
            d for d in dirs if d not in SKIP_DIRS and not (here / d / "pyvenv.cfg").exists()
        )
        found += [
            PurePosixPath(here.relative_to(root).as_posix(), f)
            for f in sorted(files)
            if f.endswith(".py")
        ]
    return [PurePosixPath(*p.parts) for p in found]


def import_path(rel: PurePosixPath) -> PurePosixPath:
    return PurePosixPath(*rel.parts[1:]) if rel.parts[0] == "src" and len(rel.parts) > 1 else rel


def scan_project(root: Path) -> ProjectScan:
    scan = ProjectScan()
    for rel in python_files(root):
        path = root.joinpath(*rel.parts)
        if path.stat().st_size > MAX_FILE_BYTES:
            continue
        import_rel = import_path(rel)
        module = module_name(str(import_rel))
        if module:
            scan.local_modules.add(module.split(".")[0])
        result = scan_source(
            path.read_text(encoding="utf-8", errors="replace"),
            module,
            is_package=import_rel.name == "__init__.py",
        )
        scan.files += 1
        if not result.parsed:
            scan.unparsed_files.append(str(rel))
        target = scan.tests if is_test_path(rel) else scan.production
        if target is scan.production:
            scan.computed_dynamic_imports += [f"{rel}:{line}" for line in result.dynamic_computed]
        target.merge(result)
    return scan
