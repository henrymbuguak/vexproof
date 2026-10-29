from __future__ import annotations

from pathlib import Path

from tests.codebase import LIBRARY, PILLOW, PROJECT, build, write_project
from tests.trees import make_tree
from vexproof.domain import Package
from vexproof.static.frameworks import django_rules, pillow_plugin_names, pillow_rules
from vexproof.static.modules import module_reachability


def test_modules_the_project_can_load(tmp_path: Path) -> None:
    reach, _, _ = build(tmp_path)
    assert reach.project_modules == {"shop", "shop.views", "shop.forms"}  # tests.py excluded
    assert reach.is_reached("PIL.Image")
    assert reach.is_reached("PIL.ImageColor")  # imported by PIL.Image
    assert reach.is_reached("PIL.IcoPlugin")  # loaded by Image.init() through _plugins
    assert not reach.is_reached("PIL.ImageMath")  # only the project's tests import it
    assert reach.blockers == []
    assert reach.reached["PIL.IcoPlugin"] == "Image.init() loads every format plugin in _plugins"
    assert reach.why("PIL.ImageColor").startswith(
        "PIL.ImageColor (imported by PIL.Image) <- PIL.Image (imported by shop.views)"
    )


def test_strings_naming_modules_reach_them(tmp_path: Path) -> None:
    project = {**PROJECT, "shop/settings.py": 'BACKEND = "PIL.ImageMath"\n'}
    reach, _, _ = build(tmp_path, project=project)
    assert reach.reached["PIL.ImageMath"] == "named in a string in shop.settings"


def test_blockers(tmp_path: Path) -> None:
    other = Package(name="otherlib", version="1.0")
    trees = {
        PILLOW: make_tree(tmp_path / "sources", PILLOW, LIBRARY),
        other: make_tree(
            tmp_path / "sources",
            other,
            {"otherlib/__init__.py": "import importlib\nimportlib.import_module(NAME)\n"},
        ),
    }
    project = {**PROJECT, "shop/loader.py": "import otherlib\nimport importlib\n"
               "importlib.import_module(name)\n"}  # fmt: skip
    root = write_project(tmp_path / "project", project)
    reach = module_reachability(root, trees, {Package(name="gone", version="1"): "404"})
    joined = " | ".join(reach.blockers)
    assert "no framework rule covers: otherlib:2" in joined
    assert "project code imports modules by computed name: shop/loader.py:3" in joined
    assert "could not read the source of gone" in joined


def test_pillow_plugin_list_parsing() -> None:
    assert pillow_plugin_names('_plugins = ["A", "B"]\n') == ["A", "B"]
    assert pillow_plugin_names("x = 1\n") == []
    assert pillow_plugin_names("def broken(:\n") == []
    assert list(pillow_rules({}, {})) == []  # PIL.Image not reached: nothing to add


def _paths(names: list[str], packages: set[str]) -> dict[str, Path]:
    return {
        n: Path(n.replace(".", "/") + ("/__init__.py" if n in packages else ".py")) for n in names
    }


def test_django_rules() -> None:
    names = [
        "django",
        "django.templatetags",
        "django.templatetags.static",
        "django.conf.locale.en.formats",
        "django.db.backends.sqlite3",
        "django.db.backends.sqlite3.base",
        "shop",
        "shop.models",
        "shop.admin",
        "shop.templatetags",
        "shop.templatetags.tags",
        "shop.helpers",
        "unused",
        "unused.models",
    ]
    packages = {"django", "django.templatetags", "django.db.backends.sqlite3", "shop", "unused",
                "shop.templatetags"}  # fmt: skip
    modules = _paths(names, packages)
    reached = {"django": "", "shop": "", "django.db.backends.sqlite3": ""}
    hits = {h.module: h.reason for h in django_rules(modules, reached)}
    assert {"shop.models", "shop.admin", "shop.templatetags", "shop.templatetags.tags"} <= set(hits)
    assert "shop.helpers" not in hits  # not a conventional submodule
    assert "unused.models" not in hits  # the app itself is not reached
    assert hits["django.templatetags.static"] == "Django builtin template library"
    assert hits["django.conf.locale.en.formats"] == "Django loads locale formats by name"
    assert "database backend" in hits["django.db.backends.sqlite3.base"]
    assert list(django_rules(modules, {"shop": ""})) == []  # Django itself not reached
