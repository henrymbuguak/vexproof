from __future__ import annotations

from collections.abc import Set as AbstractSet
from pathlib import Path

import pytest

from tests.trees import make_tree
from vexproof.domain import Package
from vexproof.sources.tree import SourceTree
from vexproof.static.closure import ModuleIndex, distribution_imports, reachability
from vexproof.static.imports import ModuleImports
from vexproof.static.levels import level0
from vexproof.static.project import ProjectScan

APP = Package(name="appframework", version="1")
LIB = Package(name="examplelib", version="1")
DEEP = Package(name="deeplib", version="1")
PLUGIN = Package(name="pluginlib", version="1")
STRINGY = Package(name="crispy-forms", version="1")
UNUSED = Package(name="unused-lib", version="1")
TESTONLY = Package(name="pytest-thing", version="1")
NS_A = Package(name="ns-a", version="1")
NS_B = Package(name="ns-b", version="1")


@pytest.fixture
def trees(tmp_path: Path) -> dict[Package, SourceTree]:
    return {
        APP: make_tree(
            tmp_path, APP, {"appframework/__init__.py": "def f():\n    import examplelib\n"}
        ),
        LIB: make_tree(tmp_path, LIB, {"examplelib/__init__.py": "from deeplib.core import x\n"}),
        DEEP: make_tree(
            tmp_path, DEEP, {"deeplib/__init__.py": "", "deeplib/core.py": "import os\n"}
        ),
        PLUGIN: make_tree(
            tmp_path,
            PLUGIN,
            {"pluginlib/__init__.py": ""},
            plugin_groups=frozenset({"app.plugins"}),
        ),
        STRINGY: make_tree(tmp_path, STRINGY, {"crispy_forms/__init__.py": ""}),
        UNUSED: make_tree(tmp_path, UNUSED, {"unused_lib/__init__.py": ""}),
        TESTONLY: make_tree(tmp_path, TESTONLY, {"pytest_thing/__init__.py": ""}),
        NS_A: make_tree(tmp_path, NS_A, {"ns/a/__init__.py": ""}),
        NS_B: make_tree(tmp_path, NS_B, {"ns/b/__init__.py": ""}),
    }


def _project(
    prod: AbstractSet[str],
    tests: AbstractSet[str] = frozenset(),
    strings: AbstractSet[str] = frozenset(),
) -> ProjectScan:
    return ProjectScan(
        production=ModuleImports(imports=set(prod), string_refs=set(strings)),
        tests=ModuleImports(imports=set(tests)),
        local_modules={"shop"},
    )


def test_index_resolves_longest_prefix_and_namespaces(trees: dict[Package, SourceTree]) -> None:
    index = ModuleIndex(trees)
    assert index.resolve("deeplib.core.x") == {DEEP}
    assert index.resolve("ns.a.thing") == {NS_A}
    assert index.resolve("ns") == {NS_A, NS_B}
    assert index.resolve("missing.mod") == set()


def test_closure_follows_imports_through_libraries(trees: dict[Package, SourceTree]) -> None:
    reach = reachability(
        _project(
            {"appframework", "shop.models", "os"},
            tests={"pytest_thing"},
            strings={"crispy_forms", "default"},
        ),
        trees,
        {},
    )
    assert reach.production == {APP, LIB, DEEP, STRINGY}  # LIB via a function-level import
    assert reach.test_only == {TESTONLY}
    assert reach.blockers == []


def test_distribution_imports_are_cached(trees: dict[Package, SourceTree]) -> None:
    first = distribution_imports(trees[LIB])
    (trees[LIB].root / "examplelib/__init__.py").write_text("import changed\n")
    assert (
        distribution_imports(trees[LIB]).imports
        == first.imports
        == {"deeplib.core", "deeplib.core.x"}
    )


def test_level0_rules(trees: dict[Package, SourceTree]) -> None:
    reach = reachability(_project({"appframework"}, tests={"pytest_thing"}), trees, {})
    assert not level0(APP, reach, trees, {}).cleared
    cleared = level0(UNUSED, reach, trees, {})
    assert cleared.cleared
    assert cleared.checks == ("not_in_import_closure",)
    test_only = level0(TESTONLY, reach, trees, {})
    assert test_only.cleared
    assert "imported_only_by_tests" in test_only.checks
    plugin = level0(PLUGIN, reach, trees, {})
    assert not plugin.cleared
    assert "plugin entry points: app.plugins" in " ".join(plugin.notes)


def test_level0_blocked_by_missing_source_or_unknown_modules(
    trees: dict[Package, SourceTree], tmp_path: Path
) -> None:
    reach = reachability(_project({"appframework"}), trees, {})
    missing = Package(name="ghost", version="1")
    assert not level0(missing, reach, trees, {missing: "not on PyPI"}).cleared
    empty = Package(name="empty", version="1")
    with_empty = {**trees, empty: make_tree(tmp_path, empty, {})}
    result = level0(empty, reach, with_empty, {})
    assert not result.cleared
    assert "no importable modules" in " ".join(result.notes)


def test_global_blockers(trees: dict[Package, SourceTree]) -> None:
    project = _project({"appframework", "unknown_module"})
    project.computed_dynamic_imports = ["app/loader.py:7"]
    reach = reachability(project, trees, {Package(name="ghost", version="1"): "down"})
    assert len(reach.blockers) == 2
    assert not level0(UNUSED, reach, trees, {}).cleared
