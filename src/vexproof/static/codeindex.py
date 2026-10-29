"""A searchable index of who mentions what, over every reachable module. Never executes code.

Each module is split into scopes: one per function or method (nested functions and lambdas fold
into the outer function, as in `functions.py`), plus one for module-level code, which includes
class bodies, decorators and default values because they run at import time. A scope records its
*sites*, each with a line number:

- `call`: something called by name, `f(...)` or `x.f(...)`;
- `attr`: an attribute read, `x.f` (bound methods passed as callbacks, properties);
- `name`: a bare name read that refers to a module-level binding (an import, a def, a class);
  local variables, parameters and builtins are left out, so `frame = 0` or `open(path)` do not
  look like mentions of a function called `frame` or `open`;
- `string`: a dotted string, such as a settings entry naming a class.

Names are resolved through the module's imports wherever the code allows: `Image.open(...)`
refers to `PIL.Image.open`, and `models.ImageField(...)` to Django's model field rather than its
form field of the same name. Classes are identified by their full dotted name, and inheritance
is followed through the imports too.

For `x.name`, what is known about `x` decides whether a hop is *certain* or only *possible*:
`self.load()` in class K can only reach a `load` of K, of a base of K or of a subclass of K;
`super().load()` only a base's; `form = PasswordResetForm(...)` fixes the class of `form`;
`self.ico = IcoFile(...)` in any method fixes the class of `self.ico`. A method called on an
object of unknown type is possible: Python decides at run time which method it reaches.

The index *finds* and *verifies* candidate call paths. A path is evidence that code can reach
a function, never proof that it cannot.
"""

from __future__ import annotations

import ast
import heapq
import math
import threading
import warnings
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Literal

from vexproof.static.modules import ModuleReach

SiteKind = Literal["call", "attr", "name", "string"]
Certainty = Literal["certain", "possible"]
BARE = "-"
LITERAL = "#literal"
_LITERALS = (ast.Constant, ast.JoinedStr, ast.List, ast.Tuple, ast.Dict, ast.Set, ast.BinOp)
_CONSTRUCTORS = frozenset({"__init__", "__new__"})
_FRAMEWORK_ENTRIES = frozenset({"__init__", "__call__"})
_MAX_STRING = 200
REGISTRATIONS = frozenset(
    {"register_open", "register_save", "register_save_all", "register_decoder", "register_encoder"}
)
# Methods of builtin types: `x.split()` on an unknown `x` is far more likely a str than a library
# method of the same name, so the path search never takes such a hop on its own. The verifier
# still accepts one when a reviewer routes a path through it on purpose.
BUILTIN_METHODS = frozenset(
    name
    for kind in (str, bytes, list, dict, set, tuple, int, float)
    for name in dir(kind)
    if not name.startswith("_")
)


@dataclass(frozen=True)
class Site:
    line: int
    name: str
    kind: SiteKind
    # who `name` is looked up on: "self", "super", "@<class>" for an object of a known class,
    # "%<name>" for a module-level name (module, class or object), "" if unknown, BARE for a
    # plain name (`f()`), LITERAL for a literal (`"{}".format()`)
    recv: str = ""
    ref: str = ""  # for f(...), mod.f(...), Class(...): the dotted path it refers to, if known


@dataclass
class Scope:
    qualname: str  # module.Class.method, module.function, or the module itself
    module: str
    kind: Literal["module", "function"]
    start: int
    end: int
    cls: str | None = None  # dotted name of the enclosing class, for methods
    sites: list[Site] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.qualname.rsplit(".", 1)[-1]

    @property
    def cls_name(self) -> str | None:
        return self.cls.rsplit(".", 1)[-1] if self.cls else None

    @property
    def is_dunder(self) -> bool:
        return self.name.startswith("__") and self.name.endswith("__")


@dataclass
class ModuleCode:
    module: str
    lines: list[str]
    scopes: dict[str, Scope]
    classes: dict[str, list[str]]  # class dotted name -> its bases, as dotted references
    registrations: dict[str, set[str]]  # register_open etc. -> names passed to it
    bindings: dict[str, str] = field(default_factory=dict)  # name -> dotted path
    star_imports: list[str] = field(default_factory=list)  # modules imported with `import *`


# -- parsing ------------------------------------------------------------------------------------


def _terminal(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _relative_base(module: str, is_package: bool, level: int) -> str | None:
    if level == 0:
        return ""
    parts = module.split(".") if is_package else module.split(".")[:-1]
    if level - 1 > len(parts):
        return None
    return ".".join(parts[: len(parts) - (level - 1)])


def _bindings(tree: ast.Module, module: str, is_package: bool) -> dict[str, str]:
    """Every name bound by an import (anywhere in the module) or a module-level def/class."""
    found: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    found[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    found.setdefault(top, top)
        elif isinstance(node, ast.ImportFrom):
            base = _relative_base(module, is_package, node.level)
            if base is None:
                continue
            source = ".".join(p for p in (base, node.module or "") if p)
            for alias in node.names:
                if alias.name != "*":
                    found[alias.asname or alias.name] = f"{source}.{alias.name}"
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            found[node.name] = f"{module}.{node.name}"
    return found


def _star_imports(tree: ast.Module, module: str, is_package: bool) -> list[str]:
    found: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names):
            base = _relative_base(module, is_package, node.level)
            if base is not None:
                found.append(".".join(p for p in (base, node.module or "") if p))
    return found


def _bound_names(nodes: Iterable[ast.AST]) -> set[str]:
    """Names bound by imports, defs, classes and assignments anywhere in `nodes`."""
    bound: set[str] = set()
    for root in nodes:
        for node in ast.walk(root):
            if isinstance(node, ast.Import | ast.ImportFrom):
                bound |= {(a.asname or a.name).split(".")[0] for a in node.names}
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                bound.add(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                bound.add(node.id)
    return bound


def _locals(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Parameters and assigned names of a function: never references to module bindings."""
    args = node.args
    params = {a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]}
    params |= {a.arg for a in (args.vararg, args.kwarg) if a is not None}
    assigned = {
        n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
    }
    imported = {
        (a.asname or a.name).split(".")[0]
        for n in ast.walk(node)
        if isinstance(n, ast.Import | ast.ImportFrom)
        for a in n.names
    }
    return (params | assigned) - imported


@dataclass(frozen=True)
class _Context:
    module: str
    module_bound: set[str]
    bindings: dict[str, str]
    local: set[str] = field(default_factory=set)
    local_types: dict[str, str] = field(default_factory=dict)  # variable -> class dotted
    attr_types: dict[str, str] = field(default_factory=dict)  # self.<attr> -> class dotted


def _dotted(node: ast.expr | None, ctx: _Context) -> str:
    """`name` or `alias.sub.attr` -> the dotted path it refers to, through the imports."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and not parts:
        name = node.value  # string annotation
        head = name.split(".")[0]
        return name if head not in ctx.bindings else ctx.bindings[head] + name[len(head) :]
    if not isinstance(node, ast.Name) or node.id in ctx.local or node.id not in ctx.bindings:
        return ""
    return ".".join([ctx.bindings[node.id], *reversed(parts)])


def _class_ref(node: ast.expr | None, ctx: _Context) -> str | None:
    """The class an annotation or constructor names, if it looks like a class."""
    name = _terminal(node) if isinstance(node, ast.Name | ast.Attribute) else None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        name = node.value.rsplit(".", 1)[-1]
    if not name or not name[:1].isupper():
        return None
    return _dotted(node, ctx) or None


def _assign_types(
    nodes: Iterable[ast.AST], target: Callable[[ast.expr], str | None], ctx: _Context
) -> dict[str, str]:
    """name -> class for `name = C(...)` / `name: C`; a name given two types is dropped."""
    types: dict[str, str] = {}
    conflicts: set[str] = set()

    def note(name: str | None, cls: str | None) -> None:
        if name is None or cls is None or name in conflicts:
            return
        if types.get(name, cls) != cls:
            conflicts.add(name)
            types.pop(name, None)
        else:
            types[name] = cls

    for root in nodes:
        for node in ast.walk(root):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                built = _class_ref(node.value.func, ctx)
                for t in node.targets:
                    note(target(t), built)
            elif isinstance(node, ast.AnnAssign):
                note(target(node.target), _class_ref(node.annotation, ctx))
    return types


def _local_name(node: ast.expr) -> str | None:
    return node.id if isinstance(node, ast.Name) else None


def _self_attr(node: ast.expr) -> str | None:
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in {"self", "cls"}
    ):
        return node.attr
    return None


def _receiver(node: ast.Attribute, ctx: _Context, imported: set[str]) -> str:  # noqa: PLR0911 - a decision table
    value = node.value
    if isinstance(value, ast.Name):
        if value.id in {"self", "cls"}:
            return "self"
        if value.id in ctx.local_types:
            return "@" + ctx.local_types[value.id]
        if value.id in ctx.local:
            return ""
        if value.id in ctx.module_bound or value.id in imported:
            return "%" + value.id  # a module, a class, or another module-level object
        return ""
    attr = _self_attr(value)
    if attr is not None and attr in ctx.attr_types:
        return "@" + ctx.attr_types[attr]
    if isinstance(value, ast.Attribute):
        root: ast.expr = value
        while isinstance(root, ast.Attribute):
            root = root.value
        if (
            isinstance(root, ast.Name)
            and root.id not in ctx.local
            and (root.id in ctx.module_bound or root.id in imported)
        ):
            return "%" + value.attr  # mod.Class.method, mod.sub.function, mod.obj.method
    if (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == "super"
    ):
        return "super"
    if isinstance(value, _LITERALS):
        return LITERAL
    return ""


def _sites(nodes: Iterable[ast.AST], ctx: _Context) -> list[Site]:
    found: set[Site] = set()
    imported_here = {
        (a.asname or a.name).split(".")[0]
        for root in nodes
        for n in ast.walk(root)
        if isinstance(n, ast.Import | ast.ImportFrom)
        for a in n.names
    }

    def is_binding(name: str) -> bool:
        """A module-level binding or an import; never a local variable or a builtin."""
        return name not in ctx.local and (name in ctx.module_bound or name in imported_here)

    called: set[int] = set()
    for root in nodes:
        for node in ast.walk(root):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute):
                called.add(id(func))
                recv = _receiver(func, ctx, imported_here)
                line = func.end_lineno or func.lineno
                found.add(Site(line, func.attr, "call", recv, _dotted(func, ctx)))
            elif isinstance(func, ast.Name) and is_binding(func.id):
                found.add(Site(func.lineno, func.id, "call", BARE, _dotted(func, ctx)))
    for root in nodes:
        for node in ast.walk(root):
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
                if id(node) not in called:
                    recv = _receiver(node, ctx, imported_here)
                    line = node.end_lineno or node.lineno
                    found.add(Site(line, node.attr, "attr", recv, _dotted(node, ctx)))
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                if is_binding(node.id):
                    found.add(Site(node.lineno, node.id, "name", BARE, _dotted(node, ctx)))
            elif (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and 0 < len(node.value) <= _MAX_STRING
                and "." in node.value
                and " " not in node.value
            ):
                found.add(Site(node.lineno, node.value, "string"))
    return sorted(found, key=lambda s: (s.line, s.name, s.kind, s.recv, s.ref))


def _headers(node: ast.If | ast.Try | ast.With) -> list[ast.AST]:
    """The expressions of a compound statement that are not inside its blocks."""
    if isinstance(node, ast.If):
        return [node.test]
    if isinstance(node, ast.Try):
        return [h.type for h in node.handlers if h.type is not None]
    return list(node.items)


def _blocks(node: ast.If | ast.Try | ast.With) -> list[list[ast.stmt]]:
    if isinstance(node, ast.If):
        return [node.body, node.orelse]
    if isinstance(node, ast.Try):
        return [node.body, *(h.body for h in node.handlers), node.orelse, node.finalbody]
    return [node.body]


def parse_module(module: str, text: str, *, is_package: bool = False) -> ModuleCode:
    lines = text.splitlines()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return ModuleCode(module, lines, {}, {}, {})
    bindings = _bindings(tree, module, is_package)
    module_bound = _bound_names(
        n for n in tree.body if not isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
    ) | {n.name for n in tree.body if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)}
    base_ctx = _Context(module, module_bound, bindings)
    scopes: dict[str, Scope] = {}
    classes: dict[str, list[str]] = {}
    registrations: dict[str, set[str]] = {}
    module_level: list[ast.AST] = []

    def visit(
        body: list[ast.stmt], prefix: str, cls: str | None, attr_types: dict[str, str]
    ) -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                dotted = f"{module}.{prefix}{node.name}"
                classes[dotted] = [d for d in (_dotted(b, base_ctx) for b in node.bases) if d]
                module_level.extend([*node.decorator_list, *node.bases, *node.keywords])
                methods = [
                    n for n in node.body if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
                ]
                own = _assign_types(methods, _self_attr, base_ctx)
                visit(node.body, f"{prefix}{node.name}.", dotted, own)
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                qualname = f"{module}.{prefix}{node.name}"
                start = min([node.lineno, *(d.lineno for d in node.decorator_list)])
                local = _locals(node)
                fn_ctx = _Context(module, module_bound, bindings, local)
                params = {
                    a.arg: t
                    for a in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                    if (t := _class_ref(a.annotation, base_ctx))
                }
                ctx = _Context(
                    module,
                    module_bound,
                    bindings,
                    local,
                    {**params, **_assign_types(node.body, _local_name, fn_ctx)},
                    attr_types,
                )
                end = node.end_lineno or node.lineno
                scopes[qualname] = Scope(
                    qualname, module, "function", start, end, cls, _sites(node.body, ctx)
                )
                module_level.extend([*node.decorator_list, *node.args.defaults])
            elif isinstance(node, ast.If | ast.Try | ast.With):
                module_level.extend(_headers(node))
                for block in _blocks(node):
                    visit(block, prefix, cls, attr_types)
            else:
                module_level.append(node)
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                    call = node.value
                    name = _terminal(call.func)
                    if name in REGISTRATIONS:
                        registrations.setdefault(name, set()).update(
                            n for n in (_terminal(a) for a in call.args) if n
                        )

    visit(tree.body, "", None, {})
    scopes[module] = Scope(
        module, module, "module", 1, len(lines) or 1, None, _sites(module_level, base_ctx)
    )
    return ModuleCode(
        module,
        lines,
        scopes,
        classes,
        registrations,
        bindings,
        _star_imports(tree, module, is_package),
    )


# -- the index ----------------------------------------------------------------------------------


class CodeIndex:
    """Lazily parsed code of every reachable module, with name lookups and a path search."""

    def __init__(self, reach: ModuleReach) -> None:
        self.reach = reach
        self._code: dict[str, ModuleCode] = {}
        self._by_name: dict[str, list[tuple[str, Site]]] = {}
        self._definitions: dict[str, int] = {}
        self._children: dict[str, set[str]] = {}
        self._parents: dict[str, list[str]] = {}
        self._classes: set[str] = set()
        self._built = False
        self._lock = threading.RLock()
        # framework routes found in project code: (caller, line, callee) -> (rule, explanation)
        self.rule_edges: dict[tuple[str, int, str], tuple[str, str]] = {}

    # -- lookups ------------------------------------------------------------------------------

    def code(self, module: str) -> ModuleCode | None:
        with self._lock:
            if module not in self._code:
                source = self.reach.modules.get(module)
                if source is None:
                    return None
                text = source.path.read_text(encoding="utf-8", errors="replace")
                self._code[module] = parse_module(
                    module, text, is_package=source.path.name == "__init__.py"
                )
            return self._code[module]

    def module_of(self, qualname: str) -> str | None:
        parts = qualname.split(".")
        for end in range(len(parts), 0, -1):
            candidate = ".".join(parts[:end])
            if candidate in self.reach.modules:
                return candidate
        return None

    def scope(self, qualname: str) -> Scope | None:
        module = self.module_of(qualname)
        code = self.code(module) if module else None
        return code.scopes.get(qualname) if code else None

    def line(self, module: str, number: int) -> str:
        code = self.code(module)
        if code is None or not 0 < number <= len(code.lines):
            return ""
        return code.lines[number - 1].strip()

    def _build(self) -> None:
        with self._lock:
            if self._built:
                return
            for module in sorted(self.reach.reached):
                code = self.code(module)
                if code is None:
                    continue
                for scope in code.scopes.values():
                    if scope.kind == "function":
                        self._definitions[scope.name] = self._definitions.get(scope.name, 0) + 1
                    for site in scope.sites:
                        self._by_name.setdefault(site.name, []).append((scope.qualname, site))
                self._classes |= set(code.classes)
            for module in sorted(self.reach.reached):
                code = self.code(module)
                for cls, bases in (code.classes if code else {}).items():
                    self._parents[cls] = [self.resolve(b) for b in bases]
                    for base in self._parents[cls]:
                        self._children.setdefault(base, set()).add(cls)
            self._built = True

    def resolve(self, dotted: str, depth: int = 6) -> str:
        """Follow re-exports: `django.forms.Form` -> `django.forms.forms.Form`.

        Through `from x import name` bindings and `from x import *` imports, a few levels deep.
        """
        for _ in range(depth):
            module = self.module_of(dotted)
            if module is None or module == dotted:
                return dotted
            head, _, rest = dotted[len(module) + 1 :].partition(".")
            following = self._lookup(module, head, set())
            if following is None:
                return dotted
            following = ".".join(p for p in (following, rest) if p)
            if following == dotted:
                return dotted
            dotted = following
        return dotted

    def _lookup(self, module: str, name: str, seen: set[str]) -> str | None:
        """Where `module.name` comes from: a binding, or a module it star-imports."""
        if module in seen:
            return None
        seen.add(module)
        code = self.code(module)
        if code is None:
            return None
        if name in code.bindings:
            return code.bindings[name]
        for source in code.star_imports:
            hit = self._lookup(source, name, seen)
            if hit is not None:
                return hit
        return None

    def is_class(self, dotted: str) -> bool:
        self._build()
        return dotted in self._classes

    def subclasses(self, cls: str) -> set[str]:
        """Dotted names of the classes that inherit from `cls`, transitively."""
        self._build()
        result: set[str] = set()
        stack = [cls]
        while stack:
            for child in self._children.get(stack.pop(), set()) - result:
                result.add(child)
                stack.append(child)
        return result

    def defines(self, cls: str, name: str) -> bool:
        return self.scope(f"{cls}.{name}") is not None

    def mro_owner(self, cls: str, name: str, *, skip_self: bool = False) -> str | None:
        """The class whose `name` an instance of `cls` uses: `cls` itself, then its bases in
        order, depth first (Python's MRO for single inheritance and simple mixins).

        None when no known class in the hierarchy defines it (a base outside the loaded code).
        """
        self._build()
        seen: set[str] = set()
        stack = list(reversed(self._parents.get(cls, []))) if skip_self else [cls]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            if self.defines(current, name):
                return current
            stack.extend(reversed(self._parents.get(current, [])))
        return None

    def dispatches_to(self, cls: str, target: Scope, *, exact: bool = False) -> bool:
        """Can calling `target.name` on an instance of `cls` run `target`?

        With `exact`, the instance's class is known to be `cls`; otherwise it may also be a
        subclass of `cls` that overrides the method. An unknown hierarchy counts as related.
        """
        assert target.cls is not None  # noqa: S101 - methods only
        owner = self.mro_owner(cls, target.name)
        if owner is None:
            return self.related(cls, target.cls)
        if owner == target.cls:
            return True
        return not exact and target.cls in self.subclasses(cls)

    def related(self, a: str, b: str) -> bool:
        """Is class `a` the same as `b`, a base of it, or a subclass of it?"""
        return a == b or a in self.subclasses(b) or b in self.subclasses(a)

    def edge(self, target: Scope, site: Site, caller: Scope | None = None) -> Certainty | None:
        """Can `site`, in `caller`, make `target` run? Certain, possible, or not at all."""
        if target.kind == "module":
            return None  # module-level code runs on import; module reach covers it
        if site.kind == "string":
            return self._string_edge(target, site)
        if target.cls is None:
            return self._function_edge(target, site)
        if target.name in _CONSTRUCTORS:
            return self._constructor_edge(target, site, caller)
        return self._method_edge(target, site, caller)

    def _string_edge(self, target: Scope, site: Site) -> Certainty | None:
        """A dotted string naming the target, or naming a class the framework builds.

        Frameworks instantiate the classes their settings name (`MIDDLEWARE`, storage and
        session backends): certain for the constructor. Calling the instance is a convention of
        some settings only (Django calls middleware for every request), so `__call__` is possible.
        """
        if site.name == target.qualname:
            return "certain"
        if target.cls is None or target.name not in _FRAMEWORK_ENTRIES:
            return None
        named = self.resolve(site.name)
        if not self.is_class(named):
            return None
        if named != target.cls and named not in self.subclasses(target.cls):
            return None
        return "certain" if target.name in _CONSTRUCTORS else "possible"

    def _function_edge(self, target: Scope, site: Site) -> Certainty | None:
        """A module-level function: called or passed by name, or as module.function."""
        if site.name != target.name or not (site.recv == BARE or site.recv.startswith("%")):
            return None
        return "certain" if site.ref and self.resolve(site.ref) == target.qualname else None

    def _constructor_edge(
        self, target: Scope, site: Site, caller: Scope | None
    ) -> Certainty | None:
        cls = target.cls
        assert cls is not None  # noqa: S101 - checked by the caller
        own = caller.cls if caller else None
        if site.kind == "call" and site.name == target.name:  # super().__init__(), C.__init__()
            if site.recv == "super":
                return "certain" if own and own in self.subclasses(cls) else None
            owner = self.resolve(site.ref.rsplit(".", 1)[0]) if site.ref else ""
            return "certain" if owner == cls else None
        if site.kind != "call":
            return None
        built = self.resolve(site.ref) if site.ref else ""
        if built:  # instantiation of the class or a subclass
            return "certain" if built == cls or built in self.subclasses(cls) else None
        short = {cls.rsplit(".", 1)[-1], *(c.rsplit(".", 1)[-1] for c in self.subclasses(cls))}
        return "possible" if site.name in short else None  # a class held in a variable

    def _method_edge(  # noqa: PLR0911 - a decision table, one return per receiver kind
        self, target: Scope, site: Site, caller: Scope | None
    ) -> Certainty | None:
        cls = target.cls
        assert cls is not None  # noqa: S101 - checked by the caller
        if site.kind not in {"call", "attr"} or site.name != target.name:
            return None
        recv = site.recv
        own = caller.cls if caller else None
        if recv in {BARE, LITERAL}:
            return None  # f() is never a method; "...".format() is a builtin type's method
        if recv == "self":  # the method K resolves to, or an override in a subclass of K
            return "certain" if own and self.dispatches_to(own, target) else None
        if recv == "super":  # the next definition above K
            above = self.mro_owner(own, target.name, skip_self=True) if own else None
            return "certain" if above == cls else None
        if recv.startswith("@"):
            known = self.resolve(recv[1:])
            if self.is_class(known):
                return "certain" if self.dispatches_to(known, target) else None
            return "possible"
        if recv.startswith("%") and site.ref:
            owner = self.resolve(site.ref.rsplit(".", 1)[0])
            if self.is_class(owner):  # Class.method(self): exactly what Class resolves to
                return "certain" if self.dispatches_to(owner, target, exact=True) else None
        if target.is_dunder:
            return None  # operators are invisible; only explicit calls count
        return "possible"

    def _candidate_names(self, target: Scope) -> set[str]:
        names = {target.name, target.qualname}
        if target.cls and target.name in _CONSTRUCTORS:
            names |= {c.rsplit(".", 1)[-1] for c in {target.cls, *self.subclasses(target.cls)}}
        if target.cls and target.name in _FRAMEWORK_ENTRIES:
            names |= {target.cls, *self.subclasses(target.cls)}  # dotted strings naming the class
        return names

    def callers(self, target: Scope) -> list[tuple[Scope, Site, Certainty]]:
        """(scope, site, certainty) for every mention of `target` in reachable code."""
        self._build()
        found: dict[tuple[str, int], tuple[Scope, Site, Certainty]] = {}
        for name in self._candidate_names(target):
            for qualname, site in self._by_name.get(name, []):
                if qualname == target.qualname:
                    continue
                scope = self.scope(qualname)
                if scope is None:
                    continue
                how = self.edge(target, site, scope)
                if how is None:
                    continue
                key = (qualname, site.line)
                if key not in found or (how == "certain" and found[key][2] != "certain"):
                    found[key] = (scope, site, how)
        return sorted(found.values(), key=lambda item: (item[0].qualname, item[1].line))

    def ambiguity(self, target: Scope) -> int:
        """How many functions share `target`'s name: a call by that name may reach any of them."""
        self._build()
        if target.name in _CONSTRUCTORS and target.cls:
            return 1  # reached by naming its class, which is distinctive
        return max(1, self._definitions.get(target.name, 1))

    def source(self, qualname: str, max_lines: int = 80) -> str | None:
        scope = self.scope(qualname)
        code = self.code(scope.module) if scope else None
        if scope is None or code is None or scope.kind == "module":
            return None
        end = min(scope.end, scope.start + max_lines - 1)
        body = [f"{n:>5}  {code.lines[n - 1]}" for n in range(scope.start, end + 1)]
        if end < scope.end:
            body.append(f"      ... ({scope.end - end} more lines)")
        return "\n".join(body)

    def registered(self, module: str, kinds: Iterable[str]) -> set[str]:
        """Dotted names passed to `register_open(...)` etc. at the top level of `module`."""
        code = self.code(module)
        if code is None:
            return set()
        return {
            f"{module}.{name}" for kind in kinds for name in code.registrations.get(kind, set())
        }

    # -- path search --------------------------------------------------------------------------

    def shortest_path(
        self,
        target: Scope,
        extra_callers: dict[str, list[tuple[Scope, int, str]]] | None = None,
        *,
        certain_only: bool = False,
        start_at: set[str] | None = None,
        avoid: set[str] | None = None,
        trusted: set[tuple[str, int, str]] | None = None,
        max_nodes: int = 20000,
    ) -> list[tuple[Scope, int, str]] | None:
        """Cheapest chain of mentions to `target`, searched backwards from it.

        The chain starts in project code, or in one of `start_at` if given. Returns
        [(scope, line where it mentions the next step, how), ..., (target, def line, "")] or
        None. With `certain_only`, only certain hops are used. Otherwise a possible hop costs more
        the more functions share the callee's name, so distinctive names win over generic ones.
        `extra_callers` adds registry dispatch edges keyed by callee; `avoid` excludes scopes;
        `trusted` hops (caller, line, callee), already judged plausible, cost like certain ones.
        """
        project = self.reach.project_modules
        best: dict[str, float] = {target.qualname: 0.0}
        nxt: dict[str, tuple[str, int, str]] = {}
        scopes: dict[str, Scope] = {target.qualname: target}
        queue: list[tuple[float, str]] = [(0.0, target.qualname)]
        expanded = 0
        while queue and expanded < max_nodes:
            cost, qualname = heapq.heappop(queue)
            if cost > best.get(qualname, math.inf):
                continue
            callee = scopes[qualname]
            arrived = qualname in start_at if start_at is not None else callee.module in project
            if arrived and qualname != target.qualname:
                path: list[tuple[Scope, int, str]] = []
                current = qualname
                while current != target.qualname:
                    following, line, how = nxt[current]
                    path.append((scopes[current], line, how))
                    current = following
                path.append((target, target.start, ""))
                return path
            expanded += 1
            step = 1.0 + math.log(self.ambiguity(callee))
            edges: list[tuple[Scope, int, str, bool]] = [
                (s, site.line, site.kind, how == "certain") for s, site, how in self.callers(callee)
            ]
            edges += [(s, ln, how, True) for s, ln, how in (extra_callers or {}).get(qualname, [])]
            for caller, line, how, sure in edges:
                if not self.reach.is_reached(caller.module) or caller.qualname in (avoid or set()):
                    continue
                certain = sure or (caller.qualname, line, qualname) in (trusted or set())
                if certain_only and not certain:
                    continue
                # reading an attribute (rather than calling it) is weaker evidence than a call
                if not certain and callee.name in BUILTIN_METHODS:
                    continue  # x.decode(), x.seek() on an unknown x: almost always the builtin
                total = cost + (1.0 if certain else 2.0 + step) + (2.0 if how == "attr" else 0.0)
                if total < best.get(caller.qualname, math.inf):
                    best[caller.qualname] = total
                    nxt[caller.qualname] = (qualname, line, how)
                    scopes[caller.qualname] = caller
                    heapq.heappush(queue, (total, caller.qualname))
        return None
