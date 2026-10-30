"""SourceTree: the importable modules of one installed distribution and where their code lives."""

from __future__ import annotations

import configparser
import json
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from vexproof.sources.archive import Extracted

# v2: modules whose file name is not an identifier (Django's `0001_initial.py`) are included.
# v3: sdists that keep code under `lib/` (SQLAlchemy, PyYAML) get the right module names.
# A new name makes trees cached by older versions rebuild once.
MANIFEST = "vexproof-tree-v3.json"
# Entry-point groups that only create executables; any other group can load code as a plugin.
SCRIPT_GROUPS = frozenset({"console_scripts", "gui_scripts"})
_SKIP_TOP = frozenset({"tests", "test", "testing", "docs", "doc", "examples", "benchmarks"})
_SKIP_FILES = frozenset({"setup.py", "conftest.py"})
# Folders sdists keep code in without being packages themselves (setup.py's package_dir).
_LAYOUT_DIRS = frozenset({"lib", "lib3", "python", "python3", "py", "py3", "source"})
_PY3_DIRS = frozenset({"lib3", "python3", "py3"})


@dataclass(frozen=True)
class SourceTree:
    dist: str
    version: str
    root: Path
    kind: str
    modules: dict[str, str] = field(
        default_factory=dict
    )  # module -> relative .py path, "" if compiled
    top_level: frozenset[str] = frozenset()
    entry_point_groups: frozenset[str] = frozenset()

    @property
    def plugin_groups(self) -> frozenset[str]:
        return self.entry_point_groups - SCRIPT_GROUPS

    def source(self, module: str) -> str | None:
        rel = self.modules.get(module)
        if not rel:
            return None
        return (self.root / rel).read_text(encoding="utf-8", errors="replace")

    def python_files(self) -> dict[str, str]:
        """Relative .py path -> module name."""
        return {rel: mod for mod, rel in self.modules.items() if rel}

    def save(self) -> None:
        payload = {
            "dist": self.dist,
            "version": self.version,
            "kind": self.kind,
            "modules": self.modules,
            "top_level": sorted(self.top_level),
            "entry_point_groups": sorted(self.entry_point_groups),
        }
        (self.root / MANIFEST).write_text(json.dumps(payload, indent=1), encoding="utf-8")

    @classmethod
    def load(cls, root: Path) -> SourceTree:
        data = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
        return cls(
            dist=data["dist"],
            version=data["version"],
            root=root,
            kind=data["kind"],
            modules=dict(data["modules"]),
            top_level=frozenset(data["top_level"]),
            entry_point_groups=frozenset(data["entry_point_groups"]),
        )


_LOADABLE = re.compile(r"\w+")


def module_name(rel: str) -> str | None:
    """`pkg/sub/mod.py` -> `pkg.sub.mod`; `pkg/__init__.py` -> `pkg`; extension modules too.

    The last part need not be an identifier: `import_module("app.migrations.0001_initial")`
    loads `0001_initial.py`, and Django does exactly that for every migration.
    """
    path = PurePosixPath(rel)
    parts = list(path.parts)
    stem = path.name.split(".", 1)[0]
    if not _LOADABLE.fullmatch(stem) or not all(p.isidentifier() for p in parts[:-1]):
        return None
    if stem == "__init__":
        return ".".join(parts[:-1]) or None
    return ".".join([*parts[:-1], stem])


def _metadata(extracted: Extracted, name: str) -> str | None:
    for path, text in extracted.metadata.items():
        if PurePosixPath(path).name == name and path.split("/")[0].endswith(".dist-info"):
            return text
    return None


def _entry_point_groups(text: str | None) -> frozenset[str]:
    if not text:
        return frozenset()
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(text)
    except configparser.Error:
        return frozenset({"<unparseable>"})
    return frozenset(parser.sections())


def _sdist_relative(rel: str) -> str | None:
    """Map an sdist path to its import path: strip `src/`, skip tests, docs and setup files."""
    parts = PurePosixPath(rel).parts
    if parts and parts[0] == "src":
        parts = parts[1:]
    if not parts or parts[0] in _SKIP_TOP or parts[-1] in _SKIP_FILES:
        return None
    return str(PurePosixPath(*parts))


def _import_root(rel: str, packages: set[str]) -> str:
    """Drop layout folders that are not packages: `lib/sqlalchemy/orm.py` -> `sqlalchemy/orm.py`.

    Many sdists keep their code under `lib/` (`package_dir={"": "lib"}`). Without this, every
    module would be named `lib.sqlalchemy...`, imports of `sqlalchemy` would find nothing, and the
    package would look unused: a wrong clear. A leading folder is dropped only when it is not a
    package itself and what follows is one, or when it is a known layout folder.
    """
    parts = PurePosixPath(rel).parts
    for i in range(len(parts) - 1):
        prefix = "/".join(parts[: i + 1])
        if prefix in packages:
            return "/".join(parts[i:]) if i else rel
        if parts[i] not in _LAYOUT_DIRS and "/".join(parts[: i + 2]) not in packages:
            return rel
    return "/".join(parts[-1:]) if all(p in _LAYOUT_DIRS for p in parts[:-1]) else rel


def _python3_first(rel: str) -> tuple[int, str]:
    """PyYAML ships `lib/yaml` (Python 2) and `lib3/yaml` (Python 3): read the Python 3 one."""
    return (0 if PurePosixPath(rel).parts[0] in _PY3_DIRS else 1, rel)


def _sdist_paths(paths: list[str]) -> dict[str, str]:
    """Import path -> file in the sdist, for every file that is package code."""
    relative = {rel: r for rel in paths if (r := _sdist_relative(rel)) is not None}
    packages = {
        str(PurePosixPath(r).parent) for r in relative.values() if r.endswith("/__init__.py")
    }
    found: dict[str, str] = {}
    for rel in sorted(relative, key=lambda r: _python3_first(relative[r])):
        found.setdefault(_import_root(relative[rel], packages), rel)
    return found


def build_tree(dist: str, version: str, kind: str, extracted: Extracted) -> SourceTree:
    modules: dict[str, str] = {}
    files = [
        rel
        for rel in extracted.python_files
        if not rel.split("/")[0].endswith((".dist-info", ".egg-info"))
        and not (".data" in rel.split("/")[0] and kind == "wheel")
    ]
    imports = {rel: rel for rel in files} if kind == "wheel" else _sdist_paths(files)
    for import_rel, rel in imports.items():
        if not import_rel.endswith(".py"):
            continue
        name = module_name(import_rel)
        if name and name not in modules:
            modules[name] = rel
    natives = list(extracted.extension_modules)
    native_imports = {rel: rel for rel in natives} if kind == "wheel" else _sdist_paths(natives)
    for import_rel in native_imports:
        name = module_name(import_rel)
        if name:
            modules.setdefault(name, "")
    declared = _metadata(extracted, "top_level.txt")
    top_level = (
        frozenset(line.strip() for line in declared.splitlines() if line.strip())
        if declared
        else frozenset(m.split(".")[0] for m in modules)
    )
    return SourceTree(
        dist=dist,
        version=version,
        root=extracted.root,
        kind=kind,
        modules=modules,
        top_level=top_level | frozenset(m.split(".")[0] for m in modules),
        entry_point_groups=_entry_point_groups(_metadata(extracted, "entry_points.txt")),
    )
