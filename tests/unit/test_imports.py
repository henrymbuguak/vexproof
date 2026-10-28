from __future__ import annotations

from pathlib import Path

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
