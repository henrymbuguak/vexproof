from __future__ import annotations

from pathlib import Path

import pytest

from vexproof.static.imports import scan_source
from vexproof.static.project import is_test_path, scan_project

SOURCE = """
import os, json as j
import examplelib.parser
from other_lib import thing
from . import sibling
from ..core import helpers
from .sub.mod import *
import importlib

def lazy():
    from nested_lib.deep import x  # imports inside functions count
    importlib.import_module("plugins.alpha")
    importlib.import_module(name)
    __import__("legacy_mod")
    import_string("pkg.backends.Backend")

INSTALLED_APPS = ["crispy_forms", "django.contrib.admin", "not a module", "x" * 1]
PATTERN = "\\d+"
"""


def test_scan_records_imports_dynamic_and_string_refs() -> None:
    found = scan_source(SOURCE, "app.views.home", is_package=False)
    assert found.parsed
    assert {
        "os", "json", "examplelib.parser", "other_lib", "other_lib.thing", "app.views",
        "app.views.sibling", "app.core", "app.core.helpers", "app.views.sub.mod", "importlib",
        "nested_lib.deep", "nested_lib.deep.x",
    } <= found.imports  # fmt: skip
    assert found.dynamic_literals == {"plugins.alpha", "legacy_mod", "pkg.backends.Backend"}
    assert found.dynamic_computed == [13]  # the importlib.import_module(name) line
    assert {"crispy_forms", "django.contrib.admin", "x"} <= found.string_refs
    assert "not a module" not in found.string_refs


def test_relative_imports_in_package_init_and_unresolvable() -> None:
    found = scan_source("from . import a\nfrom .b import c\n", "pkg", is_package=True)
    assert found.imports == {"pkg", "pkg.a", "pkg.b", "pkg.b.c"}
    assert scan_source("from ... import x\n", "pkg.mod").imports == set()
    assert scan_source("from . import x\n", None).imports == set()


def test_python2_file_falls_back_to_line_scan() -> None:
    text = "import urllib2, StringIO\nfrom .compat import (a,\n b)\nprint 'hello'\n"
    found = scan_source(text, "lib.mod")
    assert not found.parsed
    assert {"urllib2", "StringIO", "lib.compat", "lib.compat.a"} <= found.imports


def test_invalid_escape_does_not_break_parsing() -> None:
    assert scan_source('import re\nR = "\\d"\n').parsed


def test_test_path_classification() -> None:
    from pathlib import PurePosixPath as P

    assert is_test_path(P("tests/unit/x.py"))
    assert is_test_path(P("app/test_views.py"))
    assert is_test_path(P("app/views_test.py"))
    assert is_test_path(P("conftest.py"))
    assert is_test_path(P("shop/tests.py"))
    assert not is_test_path(P("app/testimonials.py"))
    assert not is_test_path(P("latest/views.py"))


def test_project_scan_separates_tests_and_skips_envs(tmp_path: Path) -> None:
    files = {
        "manage.py": "import os\n",
        "shop/__init__.py": "",
        "shop/models.py": "from django.db import models\nfrom .views import v\n",
        "shop/tests.py": "import pytest\n",
        "src/lib/__init__.py": "import importlib\nimportlib.import_module(name)\n",
        ".venv/lib/x.py": "import should_not_appear\n",
        "envdir/pyvenv.cfg": "",
        "envdir/lib.py": "import also_not\n",
        "node_modules/x.py": "import nope\n",
        "bad-dir/script.py": "import requests\n",
    }
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text)
    scan = scan_project(tmp_path)
    assert scan.files == 6
    assert scan.local_modules == {"manage", "shop", "lib"}
    assert "django.db.models" in scan.production.imports
    assert "shop.views.v" in scan.production.imports
    assert "requests" in scan.production.imports
    assert "pytest" in scan.tests.imports
    assert "pytest" not in scan.production.imports
    assert not {"should_not_appear", "also_not", "nope"} & scan.production.imports
    assert scan.computed_dynamic_imports == ["src/lib/__init__.py:2"]


# -- what a computed import's name is made of (ADR 0022) ---------------------------------------


@pytest.mark.parametrize(
    ("call", "kind", "prefix", "suffix"),
    [
        # passed in as it is: the census's django-compressor, cacheops, boto3, django-extensions
        ("import_module(mod_name)", "plain", "", ""),
        ("__import__(name)", "plain", "", ""),
        ("import_string(self.backend)", "plain", "", ""),
        ("import_module(BACKENDS[key])", "plain", "", ""),
        ("import_module(getattr(settings, 'CACHEOPS_BACKEND'))", "plain", "", ""),
        # built with literal text around a variable part
        ('import_module("%s.base" % engine)', "pattern", "", ".base"),
        ('import_module("pkg.backends." + name)', "pattern", "pkg.backends.", ""),
        ('import_module("pkg." + name + ".models")', "pattern", "pkg.", ".models"),
        ('import_module(f"pkg.plugins.{name}")', "pattern", "pkg.plugins.", ""),
        ('import_module("pkg.{}.tasks".format(app))', "pattern", "pkg.", ".tasks"),
        ('import_module("%(app)s.signals" % values)', "pattern", "", ".signals"),
        # __name__ and __package__ are known: the module's own name
        ('import_module(f"{__name__}.{name}")', "pattern", "app.views.", ""),
        ('import_module(__package__ + "." + name)', "pattern", "app.", ""),
        # built with nothing literal to match
        ('import_module("%s" % path)', "opaque", "", ""),
        ('import_module("".join(parts))', "opaque", "", ""),
        ('import_module(f"{a}{b}")', "opaque", "", ""),
        ("import_module(a + b)", "opaque", "", ""),
    ],
)
def test_computed_imports_are_classified(call: str, kind: str, prefix: str, suffix: str) -> None:
    found = scan_source(f"import importlib\n{call}\n", "app.views", is_package=False)
    assert found.dynamic_computed == [2]
    (computed,) = found.computed
    assert (computed.line, computed.kind, computed.prefix, computed.suffix) == (
        2,
        kind,
        prefix,
        suffix,
    )


def test_a_pattern_matches_only_modules_with_both_ends() -> None:
    (backends,) = scan_source('import_module("pkg.backends." + name)\n', "x").computed
    assert backends.matches("pkg.backends.redis")
    assert backends.matches("pkg.backends.sql.postgres")
    assert not backends.matches("pkg.backends.")  # the variable part is never empty
    assert not backends.matches("pkg.models")
    (base,) = scan_source('import_module("%s.base" % engine)\n', "x").computed
    assert base.matches("django.db.backends.sqlite3.base")
    assert not base.matches("django.db.backends.sqlite3.operations")
    (plain,) = scan_source("import_module(name)\n", "x").computed
    assert not plain.matches("anything")  # only patterns match by name


# -- relative names, fromlist and discovery: soundness fixes found by reading real blockers -----


@pytest.mark.parametrize(
    ("call", "literals"),
    [
        # a relative name resolves against its package, as importlib does
        ('import_module(".admin", "shop.apps")', {"shop.apps.admin"}),
        ('import_module("..models", package="shop.apps")', {"shop.models"}),
        ('import_module(".tasks", __name__)', {"app.views.tasks"}),
        ('import_module(".tasks", __package__)', {"app.tasks"}),
        # __import__ with a fromlist loads each entry as a submodule
        ('__import__("pkg", fromlist=["alpha", "beta"])', {"pkg", "pkg.alpha", "pkg.beta"}),
        ('__import__("pkg", None, None, ["gamma"])', {"pkg", "pkg.gamma"}),
    ],
)
def test_relative_and_fromlist_imports_reach_their_submodules(
    call: str, literals: set[str]
) -> None:
    found = scan_source(f"{call}\n", "app.views")
    assert found.dynamic_literals == literals
    assert found.dynamic_computed == []


@pytest.mark.parametrize(
    ("call", "prefix", "suffix", "literals"),
    [
        # a computed fromlist: anything under the package
        ("__import__(__name__, fromlist=[locale])", "app.views.", "", {"app.views"}),
        # a relative built name resolves its literal part against the package
        ('import_module(f".{name}", __name__)', "app.views.", "", set()),
        ('import_module("." + name, "plugins")', "plugins.", "", set()),
        # relative to a package passed in: only the end of the name is known
        ('import_module(".admin", app)', "", ".admin", set()),
    ],
)
def test_partly_known_relative_and_fromlist_imports_become_patterns(
    call: str, prefix: str, suffix: str, literals: set[str]
) -> None:
    found = scan_source(f"{call}\n", "app.views")
    (computed,) = found.computed
    assert (computed.kind, computed.prefix, computed.suffix) == ("pattern", prefix, suffix)
    assert found.dynamic_literals == literals


@pytest.mark.parametrize(
    "call",
    [
        "pkgutil.iter_modules([path])",
        "pkgutil.walk_packages(pkg.__path__)",
        "os.listdir(path)",
        "os.walk(root)",
        "os.scandir(path)",
        "Path(path).iterdir()",
        "glob.glob(pattern)",
        "importlib.metadata.entry_points()",
        "pkg_resources.iter_entry_points('plugins')",
    ],
)
def test_listing_packages_directories_or_entry_points_is_discovery(call: str) -> None:
    assert scan_source(f"{call}\n", "lib.loading").discovers


def test_other_calls_named_walk_are_not_discovery() -> None:
    assert not scan_source("ast.walk(tree)\n", "lib.x").discovers
    assert not scan_source("import_module(name)\n", "lib.x").discovers


def test_project_scan_skips_links_out_of_the_repository_or_to_nothing(tmp_path: Path) -> None:
    # a cloned repository is data: a link may point at an uncloned submodule, or at the
    # machine's own files
    (tmp_path / "outside.py").write_text("import secret_module\n")
    repo = tmp_path / "repo"
    (repo / "shop").mkdir(parents=True)
    (repo / "shop/views.py").write_text("import requests\n")
    (repo / "shop/linked.py").symlink_to(repo / "shop/views.py")
    (repo / "shop/away.py").symlink_to(tmp_path / "outside.py")
    (repo / "shop/broken.py").symlink_to(repo / "common/missing.py")
    scan = scan_project(repo)
    assert scan.files == 2  # views.py and the link that stays inside
    assert "secret_module" not in scan.production.imports
