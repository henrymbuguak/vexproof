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

A strict clear is refused when something could load modules the closure cannot see: a computed
import that no framework rule covers, a package whose source could not be read, or project code
that imports by computed name. Dotted names in the repository's configuration files join the
closure too.

ADR 0022 adds a second, wider closure for *assumed* clears. It assumes configuration names no
module beyond the code and repository files, and that every installed package is scanned. Under
that assumption a library's computed import that passes a name in (`import_module(mod_name)`)
loads something the closure already holds, and one built around literal text
(`"%s.base" % engine`) loads an installed module matching that pattern, so every match joins the
wider closure. Those imports block only strict clears; an opaque built name, project code that
imports by computed name and unreadable sources block both.
"""

from __future__ import annotations

import json
import os
import re
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from vexproof.domain import Package
from vexproof.sources.tree import SourceTree, module_name
from vexproof.static.frameworks import COVERED_DYNAMIC_IMPORTS, RULES, covered_module
from vexproof.static.imports import ComputedImport, ModuleImports, scan_source
from vexproof.static.project import (
    MAX_FILE_BYTES,
    SKIP_DIRS,
    import_path,
    is_test_path,
    python_files,
)

_CACHE = "vexproof-modules.v4.json"  # v4: what each computed import's name is made of
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
    # ADR 0022: modules only the wider, assumed closure reaches, the library computed imports an
    # assumed clear rests on ("module:line"), and reasons no assumed clear is possible either
    assumed_reached: dict[str, str] = field(default_factory=dict)
    assumed_on: list[str] = field(default_factory=list)
    assumed_blockers: list[str] = field(default_factory=list)

    def is_reached(self, module: str) -> bool:
        return module in self.reached

    def is_reached_assuming(self, module: str) -> bool:
        """Reached in the wider closure of ADR 0022."""
        return module in self.reached or module in self.assumed_reached

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
                computed=[ComputedImport(**c) for c in v["computed"]],
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
            "computed": [
                {"line": c.line, "kind": c.kind, "prefix": c.prefix, "suffix": c.suffix}
                for c in s.computed
            ],
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


Seed = tuple[str | None, str]  # a module to add, and why


def _close(
    reach: ModuleReach,
    scans: Mapping[str, ModuleImports],
    seeds: Iterable[Seed] | None = None,
) -> None:
    """Grow `reach.reached` until no import, string or rule adds a module.

    Without `seeds`, growth starts from project code, then the modules named in configuration
    files are added; with them, growth continues from those modules. Breadth-first, so each
    module's recorded reason is a shortest chain from project code: `why()` then explains
    `django.contrib.auth.forms` through the admin your code mounts, not through a test runner
    named in Django's default settings.
    """
    frontier: deque[str] = deque()

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

    if seeds is None:
        for module in sorted(reach.project_modules):
            add(module, "project code")
    else:
        for name, reason in seeds:
            add(resolve(name) if name else None, reason)
    while frontier:
        while frontier:
            module = frontier.popleft()
            scan = scans[module]
            for name in sorted(scan.imports | scan.dynamic_literals):
                add(resolve(name), f"imported by {module}", module)
            in_project = module in reach.project_modules
            for name in sorted(scan.string_refs):
                if "." not in name and not in_project:
                    # A bare word in library code ("py" as a Pygments language, "json" as a
                    # format) is not evidence of a module reference. Project code keeps every
                    # string: Django's INSTALLED_APPS lists one-word apps. A library that does
                    # import such a word by name passes it to an import function, which is a
                    # literal import or a computed one, recorded separately.
                    continue
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
    _close(reach, scans, config_seeds(project_root))  # strict: configuration files only widen it

    def uncovered(reached: Iterable[str]) -> list[tuple[str, ComputedImport]]:
        return sorted(
            (
                (m, c)
                for m in reached
                if reach.modules[m].owner not in COVERED_DYNAMIC_IMPORTS | {PROJECT}
                and not covered_module(m)
                for c in _computed(scans[m])
            ),
            key=lambda mc: (mc[0], mc[1].line),
        )

    strict = uncovered(reach.reached)
    if strict:
        reach.blockers.append(
            "reached code imports modules by computed name that no framework rule covers: "
            + ", ".join(f"{m}:{c.line}" for m, c in strict[:3])
        )
    shared: list[str] = []  # blockers of assumed clears too
    if computed_in_project:
        shared.append(
            "project code imports modules by computed name: " + ", ".join(computed_in_project[:3])
        )
    if failures:
        names = ", ".join(sorted(p.name for p in failures)[:5])
        shared.append(f"could not read the source of {names}, so its imports are unknown")
    reach.blockers += shared
    _assume(reach, scans, uncovered, shared)
    return reach


def _computed(scan: ModuleImports) -> list[ComputedImport]:
    """A module's computed imports; scans cached without kinds count every one as opaque."""
    if scan.computed or not scan.dynamic_computed:
        return scan.computed
    return [ComputedImport(line, "opaque") for line in scan.dynamic_computed]


def _assume(
    reach: ModuleReach,
    scans: Mapping[str, ModuleImports],
    uncovered: Callable[[Iterable[str]], list[tuple[str, ComputedImport]]],
    shared: list[str],
) -> None:
    """Grow the wider closure of ADR 0022 and record what an assumed clear rests on."""
    wide = ModuleReach(
        modules=reach.modules,
        reached=dict(reach.reached),
        via=dict(reach.via),
        project_modules=reach.project_modules,
    )
    while True:
        patterns = [c for _, c in uncovered(wide.reached) if c.kind == "pattern"]
        matches = sorted(
            m for m in wide.modules if m not in wide.reached and any(p.matches(m) for p in patterns)
        )
        if not matches:
            break
        _close(wide, scans, [(m, "matches a computed import's name pattern") for m in matches])
    reach.assumed_reached = {m: r for m, r in wide.reached.items() if m not in reach.reached}
    for m in reach.assumed_reached:
        if m in wide.via:
            reach.via.setdefault(m, wide.via[m])  # so why() explains assumed modules too
    relied = uncovered(wide.reached)
    reach.assumed_on = [f"{m}:{c.line}" for m, c in relied if c.kind != "opaque"]
    opaque = [f"{m}:{c.line}" for m, c in relied if c.kind == "opaque"]
    reach.assumed_blockers = list(shared)
    if opaque:
        reach.assumed_blockers.insert(
            0,
            "reached code builds a module name with nothing literal to match: "
            + ", ".join(opaque[:3]),
        )


_CONFIG_SUFFIXES = (".yaml", ".yml", ".toml", ".ini", ".cfg", ".json")
_CONFIG_NAME = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+")


def config_seeds(project_root: Path) -> list[Seed]:
    """Dotted names in the repository's configuration files, which can name modules to load."""
    seeds: list[Seed] = []
    for rel in config_files(project_root):
        path = project_root.joinpath(*rel.parts)
        text = path.read_text(encoding="utf-8", errors="replace")
        for name in sorted(set(_CONFIG_NAME.findall(text))):
            seeds.append((name, f"named in {rel}"))
    return seeds


def config_files(root: Path) -> list[PurePosixPath]:
    """Configuration files outside test and skipped folders (ADR 0022, section 3)."""
    found: list[PurePosixPath] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(files):
            if not (name.endswith(_CONFIG_SUFFIXES) or name == ".env" or name.startswith(".env.")):
                continue
            rel = PurePosixPath(Path(current, name).relative_to(root).as_posix())
            path = root.joinpath(*rel.parts)
            if is_test_path(rel) or path.stat().st_size > MAX_FILE_BYTES:
                continue
            found.append(rel)
    return found
