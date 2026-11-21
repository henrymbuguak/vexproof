from __future__ import annotations

from pathlib import Path

import pytest

from tests.codebase import LIBRARY, PILLOW, PROJECT, build, write_project
from tests.trees import make_tree
from vexproof.domain import Package
from vexproof.static.frameworks import (
    covered_module,
    django_rules,
    pillow_plugin_names,
    pillow_rules,
)
from vexproof.static.modules import ModuleReach, config_files, module_reachability


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
    # django-compressor 2.4, reviewed site by site; its other modules are not covered
    assert covered_module("compressor.base")
    assert covered_module("compressor.management.commands.compress")
    assert not covered_module("compressor.templatetags.compress")
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


# -- ADR 0022: configuration files, discovery and compiled code -----------------------------


def test_configuration_files_name_modules_to_load(tmp_path: Path) -> None:
    configured = {**PROJECT, "config/app.yaml": "cache:\n  backend: PIL.ImageMath\n"}
    reach, _, _ = build(tmp_path / "a", project=configured)
    assert reach.reached["PIL.ImageMath"] == "named in config/app.yaml"
    assert reach.blockers == []  # a configuration file only widens the closure
    # a test folder's configuration is not production configuration
    in_tests = {**PROJECT, "tests/fixtures.yaml": "backend: PIL.ImageMath\n"}
    reach, _, _ = build(tmp_path / "b", project=in_tests)
    assert not reach.is_reached("PIL.ImageMath")


def test_configuration_links_out_of_the_repository_or_to_nothing_are_skipped(
    tmp_path: Path,
) -> None:
    # readthedocs: `.isort.cfg -> common/isort.cfg`, where common/ is an uncloned submodule
    (tmp_path / "home.yaml").write_text("backend: PIL.ImageMath\n")
    root = write_project(tmp_path / "p", PROJECT)
    (root / ".isort.cfg").symlink_to(root / "common/isort.cfg")
    (root / "app.yaml").symlink_to(tmp_path / "home.yaml")
    (root / "real.yaml").write_text("backend: PIL.ImageMath\n")
    (root / "same.yaml").symlink_to(root / "real.yaml")
    assert [str(p) for p in config_files(root)] == ["real.yaml", "same.yaml"]


def test_a_library_that_discovers_modules_has_all_of_them_reached(tmp_path: Path) -> None:
    # Like Faker, it lists its providers' folders in one module and imports each name in another:
    # the names come from the file system, so every module of the library can load.
    lib = Package(name="fakelib", version="1.0")
    trees = {
        PILLOW: make_tree(tmp_path / "sources", PILLOW, LIBRARY),
        lib: make_tree(
            tmp_path / "sources",
            lib,
            {
                "fakelib/__init__.py": "from fakelib import factory\n",
                "fakelib/loading.py": (
                    "import os\n\ndef names(path):\n    return os.listdir(path)\n"
                ),
                "fakelib/factory.py": (
                    "import importlib\nfrom fakelib import loading\n\ndef create(path):\n"
                    "    return importlib.import_module(path)\n"
                ),
                "fakelib/providers/__init__.py": "",
                "fakelib/providers/address.py": "import PIL.ImageMath\n",
            },
        ),
    }
    project = {**PROJECT, "shop/settings.py": "import fakelib\n"}
    reach = module_reachability(write_project(tmp_path / "p", project), trees, {})
    assert reach.blockers[0].startswith(
        "reached code imports modules by computed name that no framework rule covers: "
        "fakelib.factory:5"
    )
    # and every module of the library is in both closures, with what it imports
    assert (
        reach.reached["fakelib.providers.address"]
        == "fakelib finds its own modules by listing them"
    )
    assert reach.is_reached("PIL.ImageMath")  # imported by a provider nothing names


def test_faker_and_plotly_are_covered_by_reviewed_rules(tmp_path: Path) -> None:
    faker = Package(name="faker", version="8.0.0")
    plotly = Package(name="plotly", version="4.14.3")
    numpy = Package(name="numpy", version="1.20.0")
    trees = {
        PILLOW: make_tree(tmp_path / "sources", PILLOW, LIBRARY),
        faker: make_tree(
            tmp_path / "sources",
            faker,
            {
                "faker/__init__.py": "from faker import factory\n",
                "faker/utils/__init__.py": "",
                "faker/utils/loading.py": (
                    "import pkgutil\nfrom importlib import import_module\n\n"
                    "def find(p):\n    return [import_module(n) for n in pkgutil.iter_modules(p)]\n"
                ),
                "faker/factory.py": (
                    "from importlib import import_module\nfrom faker.utils import loading\n\n"
                    "def create(path):\n    return import_module(path)\n"
                ),
                "faker/providers/__init__.py": "",
                "faker/providers/address/__init__.py": "",
                "faker/providers/address/en_US/__init__.py": "import PIL.ImageMath\n",
            },
        ),
        plotly: make_tree(
            tmp_path / "sources",
            plotly,
            {
                "plotly/__init__.py": "from _plotly_utils import optional_imports\n",
                "plotly/validators/__init__.py": "",
                "plotly/validators/bar.py": "",
                "_plotly_utils/__init__.py": "",
                "_plotly_utils/optional_imports.py": (
                    "from importlib import import_module\n\n"
                    "def get_module(name):\n    return import_module(name)\n"
                ),
            },
        ),
        numpy: make_tree(tmp_path / "sources", numpy, {"numpy/__init__.py": ""}),
    }
    project = {
        **PROJECT,
        "shop/settings.py": "import faker\nimport plotly\nimport shop.fakes\n",
        "shop/fakes/__init__.py": "from faker.providers import BaseProvider\n",
        "shop/fakes/en_GB/__init__.py": "",
    }
    reach = module_reachability(write_project(tmp_path / "p", project), trees, {})
    assert reach.blockers == []
    assert reach.is_reached("PIL.ImageMath")  # through a provider Faker finds by listing
    assert reach.is_reached("plotly.validators.bar")  # plotly's own modules, by computed name
    assert reach.is_reached("numpy")  # a one-word name plotly passes to get_module


def test_faker_may_load_the_locales_of_a_custom_provider_package(tmp_path: Path) -> None:
    from vexproof.static.frameworks import faker_rules

    modules = {
        "faker": tmp_path / "faker" / "__init__.py",
        "mylib": tmp_path / "mylib" / "__init__.py",
        "mylib.en_GB": tmp_path / "mylib" / "en_GB" / "__init__.py",
        "other": tmp_path / "other" / "__init__.py",
        "other.sub": tmp_path / "other" / "sub.py",
    }
    for name, path in modules.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("from faker.providers import BaseProvider\n" if name == "mylib" else "")
    hits = {h.module for h in faker_rules(modules, {"faker": "x", "mylib": "x", "other": "x"})}
    assert "mylib.en_GB" in hits
    assert "other.sub" not in hits


def test_reviewed_frameworks_are_not_treated_as_discovering(tmp_path: Path) -> None:
    # Django and Pillow list packages too, but their discovery is covered by framework rules.
    library = {
        **LIBRARY,
        "PIL/ImageFont.py": "import os\n\ndef fonts(d):\n    return os.listdir(d)\n",
    }
    reach, _, _ = build(tmp_path, library=library)
    assert not reach.is_reached("PIL.ImageMath")


def test_psycopg2s_compiled_code_reaches_the_modules_it_imports(tmp_path: Path) -> None:
    psycopg2 = Package(name="psycopg2", version="2.8.6")
    files = {"psycopg2/__init__.py": "from psycopg2._psycopg import connect\n"}
    files |= {f"psycopg2/{n}.py": "" for n in ("errors", "extensions", "extras", "sql", "tz")}
    files["psycopg2/pool.py"] = ""  # not imported by the extension: stays unreached
    trees = {psycopg2: make_tree(tmp_path / "sources", psycopg2, files)}
    project = {**PROJECT, "shop/settings.py": "import psycopg2\n"}
    reach = module_reachability(write_project(tmp_path / "p", project), trees, {})
    assert reach.reached["psycopg2.errors"] == "psycopg2's compiled extension imports it on load"
    assert all(reach.is_reached(f"psycopg2.{n}") for n in ("extensions", "extras", "sql", "tz"))
    assert not reach.is_reached("psycopg2.pool")


def _yaml_project(tmp_path: Path, version: str, loads: str) -> ModuleReach:
    yaml = Package(name="pyyaml", version=version)
    trees = {
        PILLOW: make_tree(tmp_path / "sources", PILLOW, LIBRARY),
        yaml: make_tree(
            tmp_path / "sources",
            yaml,
            {
                "yaml/__init__.py": f"__version__ = '{version}'\nfrom yaml.constructor import *\n",
                "yaml/constructor.py": (
                    "def find_python_module(name, unsafe=False):\n"
                    "    if unsafe:\n        __import__(name)\n"
                ),
            },
        ),
    }
    project = {**PROJECT, "shop/settings.py": f"import yaml\n\ndef read(s):\n    return {loads}\n"}
    return module_reachability(write_project(tmp_path / "p", project), trees, {})


@pytest.mark.parametrize(
    ("version", "loads", "blocked"),
    [
        ("5.4.1", "yaml.safe_load(s)", False),
        ("5.4.1", "yaml.load(s, Loader=yaml.SafeLoader)", False),
        ("5.4.1", "yaml.load(s, Loader=yaml.Loader)", True),  # data can name any module
        ("5.4.1", "yaml.unsafe_load(s)", True),
        ("5.4.1", "yaml.load(s, Loader=yaml.CUnsafeLoader)", True),
        ("3.13", "yaml.safe_load(s)", True),  # before 5.1, yaml.load was unsafe by default
    ],
)
def test_pyyaml_is_covered_only_while_no_reached_code_uses_an_unsafe_loader(
    tmp_path: Path, version: str, loads: str, blocked: bool
) -> None:
    reach = _yaml_project(tmp_path, version, loads)
    assert bool(reach.blockers) is blocked
    if blocked:
        assert "yaml.constructor:3" in reach.blockers[0]


def test_babybuddy_libraries_are_reviewed_module_by_module() -> None:
    for module in (
        "boto3.utils",
        "defusedxml.common",
        "rest_framework.settings",
        "tablib.formats",
        "whitenoise.runserver_nostatic.management.commands.runserver",
    ):
        assert covered_module(module)
    assert not covered_module("rest_framework.views")
    assert not covered_module("yaml.constructor")  # only on a condition
