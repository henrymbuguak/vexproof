"""Collect what a Python module imports, by parsing it (never executing it).

Recorded per module:
- `imports`: absolute dotted names from `import` / `from ... import` (relative ones resolved),
  including imports inside functions and `try` blocks;
- `dynamic_literals`: names passed as string literals to import_module / __import__ /
  import_string;
- `dynamic_computed`: calls to those functions with a computed (non-literal) name, each with
  what the name is made of (`ComputedImport`, ADR 0022);
- `string_refs`: string constants shaped like dotted module paths, e.g. Django's
  INSTALLED_APPS entries, which frameworks import by name at run time.
"""

from __future__ import annotations

import ast
import re
import warnings
from dataclasses import dataclass, field
from typing import Literal

ComputedKind = Literal["plain", "pattern", "opaque"]


@dataclass(frozen=True)
class ComputedImport:
    """One computed import and what its name is made of (ADR 0022).

    - `plain`: the name is passed in as it is (a variable, attribute, subscript or call result);
    - `pattern`: the name is built with literal text around a variable part, so it can only be an
      installed module whose name starts with `prefix` and ends with `suffix`;
    - `opaque`: the name is built with nothing literal to match.
    """

    line: int
    kind: ComputedKind
    prefix: str = ""
    suffix: str = ""

    def matches(self, module: str) -> bool:
        return (
            self.kind == "pattern"
            and len(module) > len(self.prefix) + len(self.suffix)
            and module.startswith(self.prefix)
            and module.endswith(self.suffix)
        )


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
    computed: list[ComputedImport] = field(default_factory=list)  # one per dynamic_computed line

    def merge(self, other: ModuleImports) -> None:
        self.imports |= other.imports
        self.dynamic_literals |= other.dynamic_literals
        self.dynamic_computed += other.dynamic_computed
        self.string_refs |= other.string_refs
        self.computed += other.computed


# `%` conversions and `str.format` fields: where a formatted name's variable parts are
_PERCENT = re.compile(r"%(?:\([^)]*\))?[#0\- +]*\d*(?:\.\d+)?[sdrifx]")
_BRACES = re.compile(r"\{[^{}]*\}")
_SELF_NAMES = frozenset({"__name__", "__package__"})


def _literal(node: ast.expr, module: str | None, is_package: bool) -> str | None:
    """The text of a string constant, or of `__name__` / `__package__`, which scanning knows."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in _SELF_NAMES and module:
        if node.id == "__name__" or is_package:
            return module
        return module.rsplit(".", 1)[0] if "." in module else ""
    return None


def _ends(parts: list[str | None]) -> tuple[str, str]:
    """Literal text before the first variable part and after the last one."""
    prefix = ""
    for part in parts:
        if part is None:
            break
        prefix += part
    suffix = ""
    for part in reversed(parts):
        if part is None:
            break
        suffix = part + suffix
    return prefix, suffix


def _template(text: str, holes: re.Pattern[str]) -> tuple[str, str] | None:
    """`"%s.base"` -> ("", ".base"); None when the template has no variable part."""
    found = list(holes.finditer(text))
    if not found:
        return None
    return text[: found[0].start()], text[found[-1].end() :]


def _add_parts(node: ast.expr, module: str | None, is_package: bool) -> list[str | None]:
    """The operands of `a + b + c`, each as its literal text or None when it is not literal."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _add_parts(node.left, module, is_package) + _add_parts(
            node.right, module, is_package
        )
    return [_literal(node, module, is_package)]


def classify(
    node: ast.expr, line: int, module: str | None = None, *, is_package: bool = False
) -> ComputedImport:
    """What a computed import's name argument is made of (see `ComputedImport`)."""
    ends: tuple[str, str] | None = None
    passed_in = isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)) or (
        isinstance(node, ast.Call) and _call_name(node) not in {"format", "join"}
    )
    if passed_in and _literal(node, module, is_package) is None:
        return ComputedImport(line, "plain")
    if isinstance(node, ast.JoinedStr):
        parts: list[str | None] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue) and not value.format_spec:
                parts.append(_literal(value.value, module, is_package))
            else:
                parts.append(None)
        ends = _ends(parts)
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        ends = _ends(_add_parts(node, module, is_package))
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        text = _literal(node.left, module, is_package)
        ends = _template(text, _PERCENT) if text is not None else None
    elif isinstance(node, ast.Call) and _call_name(node) == "format":
        owner = node.func.value if isinstance(node.func, ast.Attribute) else None
        text = _literal(owner, module, is_package) if owner is not None else None
        ends = _template(text, _BRACES) if text is not None else None
    if ends is None or not any(ends):
        return ComputedImport(line, "opaque")
    return ComputedImport(line, "pattern", prefix=ends[0], suffix=ends[1])


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
                found.computed.append(classify(first, node.lineno, module, is_package=is_package))
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
