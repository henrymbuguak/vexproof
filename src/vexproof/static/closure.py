"""Which installed distributions can the project's code reach, directly or through others?

The closure is computed over distributions: the project's imports (plus framework strings such
as INSTALLED_APPS entries) select the first distributions, then each reached distribution's own
imports pull in more, until nothing new appears. It deliberately over-approximates: an import
anywhere in a distribution, even inside a rarely used function, counts.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from vexproof.domain import Package
from vexproof.sources.tree import SourceTree
from vexproof.static.imports import ModuleImports, scan_source
from vexproof.static.project import ProjectScan

_IMPORTS_CACHE = "vexproof-imports.v3.json"  # v3: follows the tree manifest
STDLIB = frozenset(sys.stdlib_module_names) | {"__future__", "__main__"}


class ModuleIndex:
    """Map an imported dotted name to the installed distribution(s) that provide it."""

    def __init__(self, trees: Mapping[Package, SourceTree]) -> None:
        self._modules: dict[str, set[Package]] = {}
        self._tops: dict[str, set[Package]] = {}
        for package, tree in trees.items():
            for module in tree.modules:
                self._modules.setdefault(module, set()).add(package)
            for top in tree.top_level:
                self._tops.setdefault(top, set()).add(package)

    def resolve(self, name: str) -> set[Package]:
        parts = name.split(".")
        for end in range(len(parts), 0, -1):
            hit = self._modules.get(".".join(parts[:end]))
            if hit:
                return set(hit)
        return set(self._tops.get(parts[0], set()))


def distribution_imports(tree: SourceTree) -> ModuleImports:
    """Everything a distribution's modules import (cached next to its extracted source)."""
    cache = tree.root / _IMPORTS_CACHE
    if cache.is_file():
        data = json.loads(cache.read_text(encoding="utf-8"))
        return ModuleImports(imports=set(data["imports"]), parsed=data["parsed"])
    total = ModuleImports()
    for module, rel in tree.modules.items():
        if not rel:
            continue
        result = scan_source(
            (tree.root / rel).read_text(encoding="utf-8", errors="replace"),
            module,
            is_package=rel.endswith("__init__.py"),
        )
        total.imports |= result.imports | result.dynamic_literals
        total.parsed = total.parsed and result.parsed
    cache.write_text(
        json.dumps({"imports": sorted(total.imports), "parsed": total.parsed}), encoding="utf-8"
    )
    return total


@dataclass
class Reachability:
    production: set[Package] = field(default_factory=set)
    test_only: set[Package] = field(default_factory=set)
    unresolved_imports: set[str] = field(default_factory=set)
    blockers: list[str] = field(default_factory=list)  # reasons no package can be cleared


def _relevant(names: Iterable[str], local: set[str]) -> set[str]:
    return {n for n in names if n.split(".")[0] not in STDLIB and n.split(".")[0] not in local}


def _expand(
    roots: set[Package],
    index: ModuleIndex,
    trees: Mapping[Package, SourceTree],
    unresolved: set[str],
) -> set[Package]:
    seen = set(roots)
    frontier = list(roots)
    while frontier:
        package = frontier.pop()
        tree = trees.get(package)
        if tree is None:
            continue
        for name in _relevant(distribution_imports(tree).imports, set()):
            hits = index.resolve(name)
            if not hits:
                unresolved.add(name.split(".")[0])
            for hit in hits - seen:
                seen.add(hit)
                frontier.append(hit)
    return seen


def reachability(
    project: ProjectScan, trees: Mapping[Package, SourceTree], failures: Mapping[Package, str]
) -> Reachability:
    index = ModuleIndex(trees)
    result = Reachability()

    def roots(found: ModuleImports) -> set[Package]:
        names = _relevant(found.imports | found.dynamic_literals, project.local_modules)
        hits: set[Package] = set()
        for name in names:
            resolved = index.resolve(name)
            if not resolved:
                result.unresolved_imports.add(name.split(".")[0])
            hits |= resolved
        for ref in _relevant(found.string_refs, project.local_modules):
            hits |= index.resolve(ref) if ref.split(".")[0] in _tops(trees) else set()
        return hits

    production_roots = roots(project.production)
    result.production = _expand(production_roots, index, trees, result.unresolved_imports)
    every = _expand(production_roots | roots(project.tests), index, trees, set())
    result.test_only = every - result.production

    if project.computed_dynamic_imports:
        shown = ", ".join(project.computed_dynamic_imports[:3])
        result.blockers.append(f"project code imports modules by computed name ({shown})")
    if failures and result.unresolved_imports:
        names = ", ".join(sorted(p.name for p in failures)[:5])
        result.blockers.append(
            f"could not read {names}, and some imports match no readable package "
            f"({', '.join(sorted(result.unresolved_imports)[:5])})"
        )
    return result


def _tops(trees: Mapping[Package, SourceTree]) -> set[str]:
    return {top for tree in trees.values() for top in tree.top_level}
