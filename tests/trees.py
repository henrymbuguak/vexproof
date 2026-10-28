"""Build SourceTrees on disk for static-analysis tests."""

from __future__ import annotations

from pathlib import Path

from vexproof.domain import Package
from vexproof.sources.tree import SourceTree, module_name


def make_tree(
    root: Path,
    package: Package,
    files: dict[str, str],
    *,
    plugin_groups: frozenset[str] = frozenset(),
    compiled: tuple[str, ...] = (),
) -> SourceTree:
    base = root / f"{package.name}-{package.version}"
    modules: dict[str, str] = {}
    for rel, text in files.items():
        path = base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        name = module_name(rel)
        assert name is not None, rel
        modules[name] = rel
    for name in compiled:
        modules[name] = ""
    return SourceTree(
        dist=package.name,
        version=package.version,
        root=base,
        kind="wheel",
        modules=modules,
        top_level=frozenset(m.split(".")[0] for m in modules),
        entry_point_groups=plugin_groups,
    )
