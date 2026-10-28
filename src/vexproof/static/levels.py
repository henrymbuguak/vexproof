"""Level 0: clear an alert when its package cannot be reached from the project's code."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from vexproof.domain import Package
from vexproof.sources.tree import SourceTree
from vexproof.static.closure import Reachability

NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"


@dataclass(frozen=True)
class Level0:
    cleared: bool
    checks: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


def level0(
    package: Package,
    reach: Reachability,
    trees: Mapping[Package, SourceTree],
    failures: Mapping[Package, str],
) -> Level0:
    """Decide whether `package` can be cleared without looking at any vulnerable function.

    Cleared only if the package is outside the production import closure AND nothing could load
    it in a way the closure cannot see: no computed dynamic imports in the project, its own
    source was readable, and it registers no plugin entry points (which frameworks load by name).
    """
    if package in reach.production:
        return Level0(
            cleared=False, notes=("imported by production code (directly or indirectly)",)
        )
    reasons: list[str] = list(reach.blockers)
    if package in failures:
        reasons.append(f"package source unavailable: {failures[package]}")
    tree = trees.get(package)
    if tree is not None and not tree.modules:
        reasons.append("no importable modules found in its source, so its import names are unknown")
    if tree is not None and tree.plugin_groups:
        reasons.append(f"registers plugin entry points: {', '.join(sorted(tree.plugin_groups))}")
    if reasons:
        return Level0(
            cleared=False,
            notes=("not imported by production code, but cannot rule out loading:", *reasons),
        )
    if package in reach.test_only:
        return Level0(
            cleared=True,
            checks=("not_in_production_import_closure", "imported_only_by_tests"),
            notes=("only test code imports this package",),
        )
    return Level0(cleared=True, checks=("not_in_import_closure",))
