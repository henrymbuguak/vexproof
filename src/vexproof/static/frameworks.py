"""How frameworks load modules by name, written down so the module closure stays conservative.

A plain import scan cannot see a module loaded with a computed name, such as
`import_module("%s.base" % ENGINE)`. Each rule below covers one such mechanism. Every computed
import in a reached module must be covered by a rule; if one is not, no module may be cleared
(see `modules.py`). Adding a framework means reading its computed imports and writing a rule.

Django 2.x, reviewed against every computed import in its source:
- settings and other strings name classes and modules (`MIDDLEWARE`, `SESSION_ENGINE`,
  `import_string(...)`): covered by the general rule that dotted strings in reached code reach
  the module they name;
- app loading imports `<app>.apps`, `<app>.models`; admin autodiscovery imports `<app>.admin`;
  the template engine imports every `<app>.templatetags.*`; management and migrations import
  `<app>.management.commands.*` and `<app>.migrations.*`;
- `django.templatetags.*` libraries are builtins; locale formats load `django.conf.locale.*`;
- the database layer imports `<ENGINE>.base` and the backend's other submodules.

Pillow: `Image.init()` imports every format plugin listed in `PIL._plugins` (or the same list in
`PIL.Image` in other versions); `PIL.features` imports names from a table of strings.

django-allauth, reviewed module by module (0.39) rather than as a whole distribution, because
its computed imports are spread out and change between versions:
- `account.forms` imports `ACCOUNT_SIGNUP_FORM_CLASS`, and `socialaccount.helpers` and
  `allauth.utils` import adapters and forms named in settings: dotted strings, covered by the
  general string rule;
- `socialaccount.providers` imports `<app>.provider` for every app in `INSTALLED_APPS`, and
  `allauth.urls` imports `<provider package>.urls` for each of them: the rule below.
Any other computed import in allauth still blocks clears.

django-debug-toolbar (1.x), module by module: panels, middleware, the show-toolbar callback,
extra signals and stack-trace filters are all imported from dotted strings in its settings or
the project's, which the string rule covers.

django-compressor (2.4), module by module: every computed import loads a name from a dotted
string, in its own `conf.py` defaults (`compressor.cache.simple_cachekey`), in a filter's literal
`callback` (`"rcssmin.cssmin"`), in a literal parser tuple (`html.parser`, `"lxml.html"`) or in the
project's `COMPRESS_*` settings, which the string rule covers. The `compress` command also imports
`loader.__module__`, a module already loaded. Its `os.walk` calls list template and static files,
which it reads, never imports.

plotly (4.14.3): `basevalidators` builds `"plotly.graph_objs" + ...`, `validator_cache`
builds `"plotly.validators." + ...`, and `importers.relative_import` is called by 1,158
generated modules, each passing its own `__name__` and literal lists: every one loads a plotly
module, and the rule below reaches all of them. `optional_imports.get_module` is passed fixed
names, many one word (`"numpy"`), which the string rule skips in library code, so the rule adds
each one that is installed. `io._sg_scraper` globs image files and imports none.

Faker (0.7 and 8.x): `config` imports the literal `'faker.providers'` and lists its subpackages;
`factory` imports provider paths a caller passes as strings (the string rule) and, for a
localized provider, `<provider>.<locale>`, a locale found by listing the provider's folder. The
rule reaches every Faker module, and every submodule of a reached package outside Faker whose
`__init__.py` mentions Faker, since such a package may be a localized custom provider.

Reviewed for babybuddy, module by module; each computed import loads a dotted string written in
code or settings, which the string rule covers:
- boto3 (1.17): `utils.lazy_call` with literal `boto3.s3.inject...` and `boto3.dynamodb...` names.
- defusedxml (0.7): the literal standard-library module each defused module wraps (`__origin__`),
  and `lxml.etree`.
- django-import-export (2.5): `IMPORT_EXPORT_TMP_STORAGE_CLASS`, and tablib format modules named
  as class attributes.
- Django REST framework (3.12): API settings, `ROOT_URLCONF`, and the `generateschema` command's
  `--generator_class`. That last one is typed by a person running a development command, which is
  outside what a scan sees, like Django's own `--settings`: a stated limit, not covered by code.
- easy-thumbnails (2.7): `THUMBNAIL_*` settings, whose defaults are dotted strings in its conf.
- tablib (3.0): its literal registry of `tablib.formats._<name>.<Class>` paths.
- whitenoise (5.2): `<app>.management.commands.runserver` for each installed app, which Django's
  app rule already reaches.

PyYAML (5.1 and later) is covered only on a condition: `constructor.find_python_module` and
`find_python_name` import a name taken from the YAML document itself, but only for the unsafe
loaders (`Loader`, `UnsafeLoader`, `unsafe_load` and their C forms). Its site counts as covered
while no reached module that mentions YAML names one of them, and the installed PyYAML is 5.1 or
later (before 5.1, `yaml.load` without a loader was unsafe). Otherwise data can name any module,
and it blocks clears.

`six` and its vendored copies (`urllib3.packages.six`, `stripe.six`, ...) import only names from
their own table of moved standard-library modules. `requests.packages` imports a literal tuple
of packages (`urllib3`, `idna`, `chardet`) that requests already imports directly.
"""

from __future__ import annotations

import ast
import functools
import re
import warnings
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

# Distributions whose computed imports have been reviewed and are covered by the rules here.
COVERED_DYNAMIC_IMPORTS = frozenset({"django", "pillow"})
# Single modules whose computed imports have been reviewed and are covered (see above).
COVERED_DYNAMIC_MODULES = frozenset(
    {
        "allauth.account.forms",
        "allauth.socialaccount.helpers",
        "allauth.socialaccount.providers",
        "allauth.urls",
        "allauth.utils",
        "compressor.base",
        "compressor.cache",
        "compressor.filters.base",
        "compressor.management.commands.compress",
        "compressor.management.commands.mtime_cache",
        "compressor.parser",
        "compressor.utils",
        "_plotly_utils.basevalidators",
        "_plotly_utils.importers",
        "_plotly_utils.optional_imports",
        "boto3.utils",
        "debug_toolbar.apps",
        "debug_toolbar.middleware",
        "debug_toolbar.panels.signals",
        "debug_toolbar.toolbar",
        "debug_toolbar.utils",
        "defusedxml.ElementTree",
        "defusedxml.common",
        "easy_thumbnails.utils",
        "faker.config",
        "faker.factory",
        "faker.utils.loading",
        "import_export.admin",
        "import_export.formats.base_formats",
        "plotly.io._sg_scraper",
        "plotly.validator_cache",
        "requests.packages",
        "rest_framework.management.commands.generateschema",
        "rest_framework.schemas.generators",
        "rest_framework.settings",
        "tablib.formats",
        "whitenoise.runserver_nostatic.management.commands.runserver",
    }
)


# Names of PyYAML's unsafe loaders and constructors; `Loader=` as a keyword does not count.
_YAML_UNSAFE = re.compile(
    r"\b(?:C?UnsafeLoader|unsafe_load(?:_all)?|(?:Unsafe)?Constructor|C?Loader)\b(?!\s*=)"
)
_YAML_VERSION = re.compile(r"""__version__\s*=\s*['"](\d+)\.(\d+)""")
_YAML_SAFE_SINCE = (5, 1)


@functools.cache
def _source(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _yaml_loads_safely(modules: Modules, reached: Reached) -> bool:
    init = modules.get("yaml")
    version = _YAML_VERSION.search(_source(init) or "") if init else None
    if version is None or (int(version[1]), int(version[2])) < _YAML_SAFE_SINCE:
        return False
    for name in reached:
        if name == "yaml" or name.startswith("yaml.") or name not in modules:
            continue
        text = _source(modules[name])
        if text is None:
            return False
        if "yaml" in text.lower() and _YAML_UNSAFE.search(text):
            return False
    return True


# Modules whose computed imports are covered only while a condition on the closure holds.
_CONDITIONAL: dict[str, Callable[[Modules, Reached], bool]] = {
    "yaml.constructor": _yaml_loads_safely,
}


def covered_given(module: str, modules: Modules, reached: Reached) -> bool:
    """Covered by a conditional rule: the condition is checked against this closure."""
    condition = _CONDITIONAL.get(module)
    return condition is not None and condition(modules, reached)


def covered_module(module: str) -> bool:
    """A module whose computed imports are reviewed and covered (see the docstring)."""
    return module in COVERED_DYNAMIC_MODULES or module == "six" or module.endswith(".six")


APP_MARKERS = ("apps", "models", "admin", "templatetags", "management", "migrations")
_APP_MODULES = ("apps", "models", "admin", "checks", "signals")
_APP_PACKAGES = ("templatetags", "management", "migrations")
_DB_BACKEND_PARENTS = ("django.db.backends", "django.contrib.gis.db.backends")


@dataclass(frozen=True)
class RuleHit:
    module: str
    reason: str


Modules = Mapping[str, Path]  # every known module -> its source file
Reached = Mapping[str, str]  # reached module -> reason


def _submodules(modules: Modules, prefix: str) -> list[str]:
    return sorted(m for m in modules if m == prefix or m.startswith(prefix + "."))


def _is_package(modules: Modules, name: str) -> bool:
    path = modules.get(name)
    return path is not None and path.name == "__init__.py"


def django_rules(modules: Modules, reached: Reached) -> Iterable[RuleHit]:  # noqa: PLR0912
    if "django" not in reached:
        return
    for name in sorted(reached):
        if not _is_package(modules, name):
            continue
        if any(f"{name}.{marker}" in modules for marker in APP_MARKERS):
            reason = f"Django loads conventional submodules of app {name}"
            for sub in _APP_MODULES:
                if f"{name}.{sub}" in modules:
                    yield RuleHit(f"{name}.{sub}", reason)
            for sub in _APP_PACKAGES:
                for module in _submodules(modules, f"{name}.{sub}"):
                    yield RuleHit(module, reason)
        if any(name.startswith(parent + ".") for parent in _DB_BACKEND_PARENTS):
            for module in _submodules(modules, name):
                yield RuleHit(module, f"Django loads the database backend {name} by name")
    for module in _submodules(modules, "django.templatetags"):
        yield RuleHit(module, "Django builtin template library")
    for module in modules:
        if module.startswith("django.conf.locale.") and module.endswith(".formats"):
            yield RuleHit(module, "Django loads locale formats by name")


def pillow_plugin_names(source: str) -> list[str]:
    """Names in a module-level `_plugins = [...]` list."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "_plugins" for t in node.targets)
            and isinstance(node.value, ast.List | ast.Tuple)
        ):
            return [
                e.value
                for e in node.value.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)
            ]
    return []


def pillow_rules(modules: Modules, reached: Reached) -> Iterable[RuleHit]:
    if "PIL.Image" not in reached:
        return
    for host in ("PIL", "PIL.Image"):
        path = modules.get(host)
        if path is None:
            continue
        for name in pillow_plugin_names(path.read_text(encoding="utf-8", errors="replace")):
            if f"PIL.{name}" in modules:
                yield RuleHit(f"PIL.{name}", "Image.init() loads every format plugin in _plugins")


def allauth_rules(modules: Modules, reached: Reached) -> Iterable[RuleHit]:
    """The provider registry imports `<app>.provider` for each installed app, and
    `allauth.urls` imports the `urls` module of each provider it registered."""
    if "allauth.socialaccount.providers" not in reached:
        return
    for name in sorted(reached):
        if _is_package(modules, name) and f"{name}.provider" in modules:
            yield RuleHit(
                f"{name}.provider", "allauth loads the provider module of every installed app"
            )
            if f"{name}.urls" in modules:
                yield RuleHit(f"{name}.urls", "allauth mounts the URLs of every provider")


# Python modules that psycopg2's compiled extension imports when it loads: read from the C
# sources of psycopg2 2.8.6 (its PyImport_ImportModule calls), after an import sweep found
# psycopg2.errors loaded but missing from the closure. psycopg2-binary installs the same modules.
PSYCOPG2_NATIVE_IMPORTS = ("errors", "extensions", "extras", "sql", "tz")


def psycopg2_rules(modules: Modules, reached: Reached) -> Iterable[RuleHit]:
    """Compiled code imports Python modules that no source scan can see (ADR 0022, limits)."""
    if "psycopg2" not in reached:
        return
    for name in PSYCOPG2_NATIVE_IMPORTS:
        if f"psycopg2.{name}" in modules:
            yield RuleHit(f"psycopg2.{name}", "psycopg2's compiled extension imports it on load")


# Every name plotly 4.14.3 passes to `_plotly_utils.optional_imports.get_module`.
PLOTLY_OPTIONAL_IMPORTS = (
    "IPython",
    "IPython.core.display",
    "IPython.display",
    "PIL.Image",
    "_plotly_geo",
    "chart_studio",
    "geopandas",
    "matplotlib",
    "nbformat",
    "numpy",
    "pandas",
    "plotly.matplotlylib",
    "psutil",
    "requests",
    "sage.all",
    "sage_salvus",
    "scipy",
    "scipy.cluster.hierarchy",
    "scipy.interpolate",
    "scipy.spatial",
    "scipy.stats",
    "shapefile",
    "shapely",
    "skimage",
)


def plotly_rules(modules: Modules, reached: Reached) -> Iterable[RuleHit]:
    """plotly's computed imports load its own modules, or the optional ones listed above."""
    if not any(m in reached for m in ("plotly", "_plotly_utils")):
        return
    for module in (*_submodules(modules, "plotly"), *_submodules(modules, "_plotly_utils")):
        yield RuleHit(module, "plotly imports its own modules by computed name")
    if "_plotly_utils.optional_imports" in reached:
        for name in PLOTLY_OPTIONAL_IMPORTS:
            if name in modules:
                yield RuleHit(name, "plotly imports it by name when installed")


def _mentions_faker(path: Path) -> bool:
    text = _source(path)
    return text is None or "faker" in text.lower()  # unreadable: it may be a provider


def faker_rules(modules: Modules, reached: Reached) -> Iterable[RuleHit]:
    """Faker imports its own providers by listing them, and locales of custom providers."""
    if "faker" not in reached:
        return
    for module in _submodules(modules, "faker"):
        yield RuleHit(module, "Faker finds its own modules by listing them")
    for name in sorted(reached):
        if name == "faker" or name.startswith("faker.") or not _is_package(modules, name):
            continue
        if _mentions_faker(modules[name]):
            for module in _submodules(modules, name):
                yield RuleHit(module, f"Faker may load locales of {name}, a custom provider")


RULES: tuple[Callable[[Modules, Reached], Iterable[RuleHit]], ...] = (
    django_rules,
    pillow_rules,
    allauth_rules,
    psycopg2_rules,
    plotly_rules,
    faker_rules,
)
