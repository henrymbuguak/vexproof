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
"""

from __future__ import annotations

import ast
import warnings
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

# Distributions whose computed imports have been reviewed and are covered by the rules here.
COVERED_DYNAMIC_IMPORTS = frozenset({"django", "pillow"})

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


RULES: tuple[Callable[[Modules, Reached], Iterable[RuleHit]], ...] = (django_rules, pillow_rules)
