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
    discovers: bool = False  # lists packages, directories or entry points (ADR 0022)

    def merge(self, other: ModuleImports) -> None:
        self.imports |= other.imports
        self.dynamic_literals |= other.dynamic_literals
        self.dynamic_computed += other.dynamic_computed
        self.string_refs |= other.string_refs
        self.computed += other.computed
        self.discovers = self.discovers or other.discovers


# `%` conversions and `str.format` fields: where a formatted name's variable parts are
_PERCENT = re.compile(r"%(?:\([^)]*\))?[#0\- +]*\d*(?:\.\d+)?[sdrifx]")
_BRACES = re.compile(r"\{[^{}]*\}")
_SELF_NAMES = frozenset({"__name__", "__package__"})
# Calls that find modules by listing something rather than naming them: a library that makes
# them can import names no code spells out (Faker lists its providers' folders, then imports
# each by name). `os.walk` is matched on its owner, since `ast.walk` and others share the name.
_DISCOVERY = frozenset(
    {
        "iter_modules", "walk_packages", "listdir", "scandir", "iterdir", "glob", "iglob",
        "rglob", "entry_points", "iter_entry_points", "get_entry_map", "contents",
    }
)  # fmt: skip


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
            _dynamic(node, module, is_package, found)
        elif isinstance(node, ast.Call) and _discovers(node):
            found.discovers = True
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
            if len(value) <= _MAX_STRING_REF and _DOTTED.match(value):
                found.string_refs.add(value)
    return found


def _discovers(node: ast.Call) -> bool:
    name = _call_name(node)
    if name == "walk":
        func = node.func
        return (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and (func.value.id == "os")
        )
    return name in _DISCOVERY


def _argument(node: ast.Call, position: int, keyword: str) -> ast.expr | None:
    if len(node.args) > position:
        return node.args[position]
    return next((k.value for k in node.keywords if k.arg == keyword), None)


def _relative(name: str, package: str) -> str | None:
    """`.sub` against `pkg.mod` -> `pkg.mod.sub`, as importlib resolves it; None if it cannot."""
    level = len(name) - len(name.lstrip("."))
    rest = name[level:]
    parts = package.split(".") if package else []
    if not parts or level - 1 >= len(parts):
        return None
    base = ".".join(parts[: len(parts) - (level - 1)])
    return f"{base}.{rest}" if rest else base


def _dynamic(node: ast.Call, module: str | None, is_package: bool, found: ModuleImports) -> None:
    """Record a call to import_module / __import__ / import_string by what it can load.

    Relative names (`import_module(".sub", package)`) resolve against their package, and
    `__import__("pkg", fromlist=[...])` loads each entry as a submodule of `pkg`: a literal entry
    by name, a computed one as anything under `pkg`. What stays computed is classified
    (`ComputedImport`).
    """
    first = node.args[0]
    line = node.lineno
    text = _literal(first, module, is_package)
    function = _call_name(node)

    def computed(found_import: ComputedImport) -> None:
        found.dynamic_computed.append(line)
        found.computed.append(found_import)

    package_node = _argument(node, 1, "package") if function == "import_module" else None
    package = _literal(package_node, module, is_package) if package_node is not None else None
    if text is not None:
        if text.startswith("."):
            resolved = _relative(text, package) if package is not None else None
            if resolved is not None:
                found.dynamic_literals.add(resolved)
            elif text.strip("."):  # relative to a package passed in: it ends with this name
                computed(ComputedImport(line, "pattern", suffix="." + text.lstrip(".")))
            else:
                computed(ComputedImport(line, "opaque"))
            return
        found.dynamic_literals.add(text)
        fromlist = _argument(node, 3, "fromlist") if function == "__import__" else None
        if fromlist is not None:
            entries = fromlist.elts if isinstance(fromlist, (ast.List, ast.Tuple)) else None
            literal = [_literal(e, module, is_package) for e in entries or ()]
            if entries is not None and all(v is not None for v in literal):
                found.dynamic_literals |= {f"{text}.{v}" for v in literal if v and v != "*"}
            else:
                computed(ComputedImport(line, "pattern", prefix=f"{text}."))
        return
    kind = classify(first, line, module, is_package=is_package)
    if kind.kind == "pattern" and kind.prefix.startswith("."):
        resolved = _relative(kind.prefix + "x", package) if package is not None else None
        if resolved is not None:  # the relative prefix, resolved, then the variable part
            kind = ComputedImport(line, "pattern", prefix=resolved[:-1], suffix=kind.suffix)
        elif kind.suffix:
            kind = ComputedImport(line, "pattern", suffix=kind.suffix)
        else:
            kind = ComputedImport(line, "opaque")
    computed(kind)


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
