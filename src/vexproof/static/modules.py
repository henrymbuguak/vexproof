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

A clear is refused when something could load modules the closure cannot see: a computed import
that no framework rule covers, a package whose source could not be read, or project code that
imports by computed name. Dotted names in the repository's configuration files join the closure
too, and so does every module of a library that finds modules by listing them (ADR 0022).

Each computed import is recorded with what its name is made of (plain, pattern or opaque) and
whether its module lists packages or directories: facts a reviewer reads before writing a
framework rule that covers it (ADR 0008).
"""

from __future__ import annotations

import json
import os
import re
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from vexproof.domain import Package
from vexproof.sources.tree import SourceTree, module_name
from vexproof.static.frameworks import (
    COVERED_DYNAMIC_IMPORTS,
    RULES,
    covered_given,
    covered_module,
)
from vexproof.static.imports import ComputedImport, ModuleImports, scan_source
from vexproof.static.project import (
    MAX_FILE_BYTES,
    SKIP_DIRS,
    import_path,
    inside_file,
    is_test_path,
    python_files,
)

_CACHE = "vexproof-modules.v5.json"  # v5: relative and fromlist imports resolved; discovery
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
                computed=[ComputedImport(**c) for c in v["computed"]],
                discovers=v["discovers"],
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
            "discovers": s.discovers,
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
    # Reviewed distributions (Django, Pillow) and modules have their discovery covered by
    # framework rules already: Django's apps, management commands and migrations rules.
    discovering = {
        reach.modules[m].owner
        for m, s in scans.items()
        if s.discovers
        and reach.modules[m].owner not in COVERED_DYNAMIC_IMPORTS | {PROJECT}
        and not covered_module(m)
    }
    _close(reach, scans)
    _close(reach, scans, config_seeds(project_root))  # strict: configuration files only widen it
    _discovered(reach, scans, discovering)

    paths = {m: s.path for m, s in reach.modules.items()}
    uncovered = sorted(
        (
            (m, c)
            for m in reach.reached
            if reach.modules[m].owner not in COVERED_DYNAMIC_IMPORTS | {PROJECT}
            and not covered_module(m)
            and not covered_given(m, paths, reach.reached)
            for c in _computed(scans[m])
        ),
        key=lambda mc: (mc[0], mc[1].line),
    )
    if uncovered:
        reach.blockers.append(
            "reached code imports modules by computed name that no framework rule covers: "
            + ", ".join(f"{m}:{c.line}" for m, c in uncovered[:3])
        )
    if computed_in_project:
        reach.blockers.append(
            "project code imports modules by computed name: " + ", ".join(computed_in_project[:3])
        )
    if failures:
        names = ", ".join(sorted(p.name for p in failures)[:5])
        reach.blockers.append(f"could not read the source of {names}, so its imports are unknown")
    return reach


def _discovered(
    reach: ModuleReach, scans: Mapping[str, ModuleImports], discovering: set[str]
) -> None:
    """A reached library that finds modules by listing them can load any module of its own.

    Faker lists the folders of `faker.providers` and imports each by name, so every module of a
    discovering distribution joins the closure once any of its modules is reached, and growth
    goes on from there (what Faker's providers import). This only widens the closure.
    """
    while True:
        owners = {reach.modules[m].owner for m in reach.reached} & discovering
        seeds = sorted(
            m for m, src in reach.modules.items() if src.owner in owners and m not in reach.reached
        )
        if not seeds:
            return
        reasons = {
            m: f"{reach.modules[m].owner} finds its own modules by listing them" for m in seeds
        }
        _close(reach, scans, [(m, reasons[m]) for m in seeds])


def _computed(scan: ModuleImports) -> list[ComputedImport]:
    """A module's computed imports; scans cached without kinds count every one as opaque."""
    if scan.computed or not scan.dynamic_computed:
        return scan.computed
    return [ComputedImport(line, "opaque") for line in scan.dynamic_computed]


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
            if is_test_path(rel) or not inside_file(path, root):
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            found.append(rel)
    return found
