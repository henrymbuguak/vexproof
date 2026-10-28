"""Collect what a Python module imports, by parsing it (never executing it).

Recorded per module:
- `imports`: absolute dotted names from `import` / `from ... import` (relative ones resolved),
  including imports inside functions and `try` blocks;
- `dynamic_literals`: names passed as string literals to import_module / __import__ /
  import_string;
- `dynamic_computed`: calls to those functions with a computed (non-literal) name;
- `string_refs`: string constants shaped like dotted module paths, e.g. Django's
  INSTALLED_APPS entries, which frameworks import by name at run time.
"""

from __future__ import annotations

import ast
import re
import warnings
from dataclasses import dataclass, field

_DOTTED = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$")
_DYNAMIC = frozenset({"import_module", "__import__", "import_string"})
_MAX_STRING_REF = 200
# Fallback for files that do not parse as Python 3 (e.g. Python 2 code in old packages).
_IMPORT_LINE = re.compile(
    r"^\s*(?:from\s+(?P<from>\.*[\w.]*)\s+import\s+(?P<names>[\w*, ()]+)"
    r"|import\s+(?P<mods>[\w., ]+))",
    re.MULTILINE,
)


@dataclass
class ModuleImports:
    imports: set[str] = field(default_factory=set)
    dynamic_literals: set[str] = field(default_factory=set)
    dynamic_computed: list[int] = field(default_factory=list)  # line numbers
    string_refs: set[str] = field(default_factory=set)
    parsed: bool = True

    def merge(self, other: ModuleImports) -> None:
        self.imports |= other.imports
        self.dynamic_literals |= other.dynamic_literals
        self.dynamic_computed += other.dynamic_computed
        self.string_refs |= other.string_refs


def _base(module: str | None, is_package: bool, level: int) -> str | None:
    """Package that a relative import of `level` dots refers to, or None if unresolvable."""
    if level == 0:
        return ""
    if module is None:
        return None
    parts = module.split(".") if is_package else module.split(".")[:-1]
    if level - 1 > len(parts):
        return None
    return ".".join(parts[: len(parts) - (level - 1)])


def _join(base: str, name: str | None) -> str:
    return ".".join(p for p in (base, name or "") if p)


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def scan_source(text: str, module: str | None = None, *, is_package: bool = False) -> ModuleImports:
    """Parse `text`; fall back to a line-based scan when it is not valid Python 3."""
    try:
        with warnings.catch_warnings():
            # Old code is full of invalid escape sequences; they are irrelevant to imports, and
            # under warnings-as-errors they would turn a valid file into a parse failure.
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return _scan_lines(text, module, is_package)
    found = ModuleImports()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.imports |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            base = _base(module, is_package, node.level)
            if base is None:
                continue
            target = _join(base, node.module)
            if target:
                found.imports.add(target)
            found.imports |= {_join(target, a.name) for a in node.names if a.name != "*"}
        elif isinstance(node, ast.Call) and _call_name(node) in _DYNAMIC and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                if first.value.startswith("."):
                    continue  # relative dynamic import; its package is already imported
                found.dynamic_literals.add(first.value)
            else:
                found.dynamic_computed.append(node.lineno)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
            if len(value) <= _MAX_STRING_REF and _DOTTED.match(value):
                found.string_refs.add(value)
    return found


def _scan_lines(text: str, module: str | None, is_package: bool) -> ModuleImports:
    found = ModuleImports(parsed=False)
    for match in _IMPORT_LINE.finditer(text):
        if match["mods"]:
            found.imports |= {
                m.strip().split(" ")[0] for m in match["mods"].split(",") if m.strip()
            }
            continue
        source = match["from"]
        level = len(source) - len(source.lstrip("."))
        base = _base(module, is_package, level)
        if base is None:
            continue
        target = _join(base, source.lstrip(".") or None)
        if target:
            found.imports.add(target)
        names = match["names"].replace("(", " ").replace(")", " ").split(",")
        found.imports |= {
            _join(target, n.strip().split(" ")[0]) for n in names if n.strip() and "*" not in n
        }
    return found
