"""Which modules can the project's code load? A module-level refinement of the import closure.

Chapter 2 asks whether a *package* is reachable. Here the question is per module: a package can
be in use while the module holding a vulnerable function is never loaded (Pillow's `ImageMath`,
Django's `contrib.gis`). Code in a module that is never loaded never runs.

Over-approximation, on purpose. A module is reached when:
- it is project production code;
- a reached module imports it anywhere, including inside functions and `try` blocks;
- a dotted string in reached code names it (settings, `import_string`, URL configs);
- a framework rule says the framework loads it by a computed name (`frameworks.py`);
- it is the parent package of a reached module.

Clearing is refused outright when something could load modules the closure cannot see: a
computed import that no framework rule covers, a package whose source could not be read, or
project code that imports by computed name.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from vexproof.domain import Package
from vexproof.sources.tree import SourceTree, module_name
from vexproof.static.frameworks import COVERED_DYNAMIC_IMPORTS, RULES
from vexproof.static.imports import ModuleImports, scan_source
from vexproof.static.project import import_path, is_test_path, python_files

_CACHE = "vexproof-modules.v2.json"  # v2: tree v2 lists more modules
PROJECT = "<project>"


@dataclass(frozen=True)
class ModuleSource:
    name: str
    path: Path
    owner: str  # distribution name, or PROJECT
    rel: str  # path shown to people: inside the package, or inside the project


@dataclass
class ModuleReach:
    modules: dict[str, ModuleSource] = field(default_factory=dict)
    reached: dict[str, str] = field(default_factory=dict)  # module -> why it is reached
    via: dict[str, str] = field(default_factory=dict)  # module -> the module that reached it
    project_modules: set[str] = field(default_factory=set)
    blockers: list[str] = field(default_factory=list)  # reasons no module may be cleared

    def is_reached(self, module: str) -> bool:
        return module in self.reached

    def why(self, module: str, limit: int = 6) -> str:
        """How `module` is reached, newest step first, e.g. `a (imported by b) <- b (...)`."""
        steps: list[str] = []
        current: str | None = module
        while current in self.reached and len(steps) < limit:
            steps.append(f"{current} ({self.reached[current]})")
            current = self.via.get(current)
        return " <- ".join(steps)


def _scan_tree(tree: SourceTree) -> dict[str, ModuleImports]:
    cache = tree.root / _CACHE
    if cache.is_file():
        data = json.loads(cache.read_text(encoding="utf-8"))
        return {
            m: ModuleImports(
                imports=set(v["imports"]),
                dynamic_literals=set(v["dynamic_literals"]),
                dynamic_computed=list(v["dynamic_computed"]),
                string_refs=set(v["string_refs"]),
                parsed=v["parsed"],
            )
            for m, v in data.items()
        }
    scans: dict[str, ModuleImports] = {}
    for module, rel in tree.modules.items():
        if not rel:
            continue
        scans[module] = scan_source(
            (tree.root / rel).read_text(encoding="utf-8", errors="replace"),
            module,
            is_package=rel.endswith("__init__.py"),
        )
    payload = {
        m: {
            "imports": sorted(s.imports),
            "dynamic_literals": sorted(s.dynamic_literals),
            "dynamic_computed": s.dynamic_computed,
            "string_refs": sorted(s.string_refs),
            "parsed": s.parsed,
        }
        for m, s in scans.items()
    }
    cache.write_text(json.dumps(payload), encoding="utf-8")
    return scans


def _load(
    project_root: Path, trees: Mapping[Package, SourceTree], reach: ModuleReach
) -> tuple[dict[str, ModuleImports], list[str]]:
    """Register every module (packages, then project code) and scan its imports."""
    scans: dict[str, ModuleImports] = {}
    for tree in trees.values():
        for module, scan in _scan_tree(tree).items():
            rel = tree.modules[module]
            reach.modules[module] = ModuleSource(module, tree.root / rel, tree.dist, rel)
            scans[module] = scan
    computed: list[str] = []
    for prel in python_files(project_root):
        if is_test_path(prel):
            continue
        name = module_name(str(import_path(prel)))
        if not name:
            continue
        path = project_root.joinpath(*prel.parts)
        scan = scan_source(
            path.read_text(encoding="utf-8", errors="replace"),
            name,
            is_package=prel.name == "__init__.py",
        )
        reach.modules[name] = ModuleSource(name, path, PROJECT, str(prel))  # project wins
        reach.project_modules.add(name)
        scans[name] = scan
        computed += [f"{prel}:{line}" for line in scan.dynamic_computed]
    return scans, computed


def _close(reach: ModuleReach, scans: Mapping[str, ModuleImports]) -> None:
    """Grow `reach.reached` from project code until no import, string or rule adds a module."""
    frontier: list[str] = []

    def add(module: str | None, reason: str, via: str | None = None) -> None:
        if module is None or module in reach.reached:
            return
        reach.reached[module] = reason
        if via:
            reach.via[module] = via
        frontier.append(module)
        parts = module.split(".")
        for end in range(len(parts) - 1, 0, -1):
            parent = ".".join(parts[:end])
            if parent in reach.modules and parent not in reach.reached:
                reach.reached[parent] = f"parent package of {module}"
                reach.via[parent] = module
                frontier.append(parent)

    def resolve(name: str) -> str | None:
        parts = name.split(".")
        for end in range(len(parts), 0, -1):
            candidate = ".".join(parts[:end])
            if candidate in reach.modules:
                return candidate
        return None

    for module in sorted(reach.project_modules):
        add(module, "project code")
    while frontier:
        while frontier:
            module = frontier.pop()
            scan = scans[module]
            for name in sorted(scan.imports | scan.dynamic_literals):
                add(resolve(name), f"imported by {module}", module)
            for name in sorted(scan.string_refs):
                add(resolve(name), f"named in a string in {module}", module)
        paths = {m: s.path for m, s in reach.modules.items()}
        for rule in RULES:
            for hit in list(rule(paths, dict(reach.reached))):
                add(hit.module, hit.reason)


def module_reachability(
    project_root: Path,
    trees: Mapping[Package, SourceTree],
    failures: Mapping[Package, str],
) -> ModuleReach:
    reach = ModuleReach()
    scans, computed_in_project = _load(project_root, trees, reach)
    _close(reach, scans)
    uncovered = sorted(
        f"{m}:{line}"
        for m in reach.reached
        if reach.modules[m].owner not in COVERED_DYNAMIC_IMPORTS | {PROJECT}
        for line in scans[m].dynamic_computed
    )
    if uncovered:
        reach.blockers.append(
            "reached code imports modules by computed name that no framework rule covers: "
            + ", ".join(uncovered[:3])
        )
    if computed_in_project:
        reach.blockers.append(
            "project code imports modules by computed name: " + ", ".join(computed_in_project[:3])
        )
    if failures:
        names = ", ".join(sorted(p.name for p in failures)[:5])
        reach.blockers.append(f"could not read the source of {names}, so its imports are unknown")
    return reach
