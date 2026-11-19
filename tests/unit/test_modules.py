from __future__ import annotations

from pathlib import Path

from tests.codebase import LIBRARY, PILLOW, PROJECT, build, write_project
from tests.trees import make_tree
from vexproof.domain import Package
from vexproof.sources.tree import SourceTree
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


def test_a_bare_word_in_library_code_names_no_module(tmp_path: Path) -> None:
    # Pygments calls a language "py"; the py package is not loaded because of it. A dotted
    # string in the same library, and a bare word in project code, still count.
    lexers = Package(name="lexers", version="1.0")
    word = Package(name="py", version="1.11.0")
    sources = tmp_path / "sources"
    trees = {
        PILLOW: make_tree(sources, PILLOW, LIBRARY),
        lexers: make_tree(
            sources,
            lexers,
            {"lexers/__init__.py": 'ALIASES = ["py", "python"]\nDEFAULT = "PIL.ImageMath"\n'},
        ),
        word: make_tree(sources, word, {"py/__init__.py": ""}),
    }
    imports_lexers = {**PROJECT, "shop/settings.py": "import lexers\n"}
    reach = module_reachability(write_project(tmp_path / "one", imports_lexers), trees, {})
    assert reach.is_reached("lexers")
    assert not reach.is_reached("py")  # a bare word in a library: not a reference
    assert reach.reached["PIL.ImageMath"] == "named in a string in lexers"  # dotted: still is
    names_py = {**PROJECT, "shop/settings.py": 'INSTALLED_APPS = ["py"]\n'}
    reach = module_reachability(write_project(tmp_path / "two", names_py), trees, {})
    assert reach.reached["py"] == "named in a string in shop.settings"  # project code: counts


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


def test_allauth_six_and_debug_toolbar_computed_imports_are_covered() -> None:
    from vexproof.static.frameworks import allauth_rules, covered_module

    assert covered_module("allauth.socialaccount.providers")
    assert covered_module("debug_toolbar.toolbar")
    assert covered_module("urllib3.packages.six")
    assert covered_module("six")
    assert not covered_module("allauth.account.views")  # only reviewed modules are covered
    assert not covered_module("sixpack")
    modules = {
        name: Path(f"/x/{name.replace('.', '/')}/__init__.py")
        for name in ("allauth.socialaccount.providers", "allauth.socialaccount.providers.google")
    }
    modules["allauth.socialaccount.providers.google.provider"] = Path("/x/p.py")
    modules["allauth.socialaccount.providers.google.urls"] = Path("/x/u.py")
    reached = dict.fromkeys(
        ["allauth.socialaccount.providers", "allauth.socialaccount.providers.google"], "r"
    )
    hits = {h.module for h in allauth_rules(modules, reached)}
    assert hits == {
        "allauth.socialaccount.providers.google.provider",
        "allauth.socialaccount.providers.google.urls",
    }
    assert list(allauth_rules(modules, {})) == []  # nothing when allauth's registry is unused


# -- ADR 0022: the strict closure, the assumed closure, and what each rests on ------------------


def _with_library(tmp_path: Path, files: dict[str, str]) -> dict[Package, SourceTree]:
    lib = Package(name="plugins", version="2.0")
    return {
        PILLOW: make_tree(tmp_path / "sources", PILLOW, LIBRARY),
        lib: make_tree(tmp_path / "sources", lib, files),
    }


PLUGINS = {
    "plugins/__init__.py": "import importlib\n",
    "plugins/loader.py": (
        "import importlib\n\ndef load(name):\n    return importlib.import_module(name)\n"
    ),
    "plugins/backends/__init__.py": "",
    "plugins/backends/redis.py": "import PIL.ImageMath\n",  # reached only if a pattern matches it
    "plugins/patterned.py": (
        "import importlib\n\ndef pick(x):\n"
        '    return importlib.import_module("plugins.backends." + x)\n'
    ),
    "plugins/opaque.py": (
        "import importlib\n\ndef pick(a, b):\n    return importlib.import_module(a + b)\n"
    ),
}


def test_a_passed_in_name_blocks_only_strict_clears(tmp_path: Path) -> None:
    trees = _with_library(tmp_path, PLUGINS)
    project = {**PROJECT, "shop/settings.py": "import plugins.loader\n"}
    reach = module_reachability(write_project(tmp_path / "p", project), trees, {})
    assert reach.blockers  # strict: as before ADR 0022
    assert reach.assumed_on == ["plugins.loader:4"]  # what an assumed clear rests on
    assert reach.assumed_blockers == []  # nothing stops an assumed clear
    assert reach.assumed_reached == {}  # a plain name adds no module


def test_a_pattern_adds_its_matches_to_the_assumed_closure_only(tmp_path: Path) -> None:
    trees = _with_library(tmp_path, PLUGINS)
    project = {**PROJECT, "shop/settings.py": "import plugins.patterned\n"}
    reach = module_reachability(write_project(tmp_path / "p", project), trees, {})
    assert not reach.is_reached("plugins.backends.redis")  # not in the strict closure
    assert reach.is_reached_assuming("plugins.backends.redis")
    assert reach.assumed_reached["plugins.backends.redis"] == (
        "matches a computed import's name pattern"
    )
    # and growth goes on from the match: what it imports is reached too
    assert not reach.is_reached("PIL.ImageMath")
    assert reach.is_reached_assuming("PIL.ImageMath")
    assert reach.assumed_on == ["plugins.patterned:4"]


def test_opaque_names_project_imports_and_unreadable_sources_block_both(tmp_path: Path) -> None:
    trees = _with_library(tmp_path, PLUGINS)
    opaque = {**PROJECT, "shop/settings.py": "import plugins.opaque\n"}
    reach = module_reachability(write_project(tmp_path / "a", opaque), trees, {})
    assert reach.assumed_blockers[0].startswith(
        "reached code builds a module name with nothing literal to match: plugins.opaque:4"
    )
    in_project = {
        **PROJECT,
        "shop/settings.py": "import importlib\nimportlib.import_module(NAME)\n",
    }
    reach = module_reachability(write_project(tmp_path / "b", in_project), trees, {})
    assert any("project code imports" in b for b in reach.assumed_blockers)
    missing = Package(name="ghost", version="1.0")
    reach = module_reachability(write_project(tmp_path / "c", PROJECT), trees, {missing: "404"})
    assert any("could not read the source of ghost" in b for b in reach.assumed_blockers)


def test_configuration_files_name_modules_for_both_closures(tmp_path: Path) -> None:
    configured = {**PROJECT, "config/app.yaml": "cache:\n  backend: PIL.ImageMath\n"}
    reach, _, _ = build(tmp_path / "a", project=configured)
    assert reach.reached["PIL.ImageMath"] == "named in config/app.yaml"
    assert reach.blockers == []  # a configuration file only widens the closure
    # a test folder's configuration is not production configuration
    in_tests = {**PROJECT, "tests/fixtures.yaml": "backend: PIL.ImageMath\n"}
    reach, _, _ = build(tmp_path / "b", project=in_tests)
    assert not reach.is_reached("PIL.ImageMath")
