"""Find and verify call paths from the project's code to a vulnerable function, hop by hop.

A path is a list of steps `(symbol, line)`: each step's `line` is where its code mentions the
next step. It is accepted only if every check holds:

- the first step is the project's own production code (a function or module-level code);
- the last step is the target function;
- every step exists and lives in a module the project can load;
- every hop is *grounded*: at the cited line, the step's code calls or refers to the next step
  (see `CodeIndex.edge`), or a named dispatch rule below applies;
- types carried along the path agree: once `form = CartAddProductForm(...)` and
  `form.is_valid()` are on the path, `self` is a `CartAddProductForm` in the hops that follow, so
  `self.clean()` there cannot reach `AuthenticationForm.clean`.

A hop is *certain* when the class of the object is known (or a function is called by name), and
*possible* when a method is called on an object of unknown type. Python decides at run time which
method such a call reaches, so a path with possible hops needs a reviewer (the model) to judge
them. A verified path is evidence that the code can reach the function; never the basis for
"not reachable".
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from vexproof.domain import Hop
from vexproof.static.codeindex import CodeIndex, Scope, Site
from vexproof.static.django_routes import admin_login_routes, admin_upload_routes

MAX_HOPS = 30
MAX_SEARCHES = 6


@dataclass(frozen=True)
class Step:
    symbol: str
    line: int


@dataclass(frozen=True)
class VerifiedPath:
    hops: tuple[Hop, ...]

    @property
    def possible_hops(self) -> int:
        return sum(1 for h in self.hops if not h.certain)

    def render(self) -> str:
        return " -> ".join(h.symbol for h in self.hops)


def route_notes(path: VerifiedPath, index: CodeIndex) -> list[str]:
    """Explanations of the framework routes a path takes."""
    hops = path.hops
    return [
        index.rule_edges[key][1]
        for i in range(1, len(hops))
        if (key := (hops[i - 1].symbol, hops[i - 1].line, hops[i].symbol)) in index.rule_edges
    ]


@dataclass(frozen=True)
class PathRejected:
    reasons: tuple[str, ...]
    blame: str | None = None  # the step whose choice made the path fail, for a new search


# -- dispatch rules: calls that go through a registry rather than a name ------------------------

Rule = Callable[[Scope, Scope, CodeIndex], bool]


def _pillow_open(caller: Scope, callee: Scope, index: CodeIndex) -> bool:
    """`Image.open` instantiates the classes plugins register with `register_open`."""
    if caller.qualname != "PIL.Image.open" or callee.name != "__init__" or callee.cls is None:
        return False
    registered = {
        name
        for module in index.reach.reached
        if module.startswith("PIL.")
        for name in index.registered(module, ["register_open"])
    }
    if callee.cls in registered:
        return True
    # ImageFile.__init__ runs for every registered plugin class that inherits it
    return bool(registered & index.subclasses(callee.cls))


def _pillow_save(caller: Scope, callee: Scope, index: CodeIndex) -> bool:
    """`Image.save` calls the function a plugin registers with `register_save(_all)`."""
    return caller.qualname == "PIL.Image.Image.save" and callee.qualname in index.registered(
        callee.module, ["register_save", "register_save_all"]
    )


DJANGO_VIEW = "django.views.generic.base.View"
HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "trace"})


def _django_view_dispatch(caller: Scope, callee: Scope, index: CodeIndex) -> bool:
    """`View.dispatch` calls the handler named by the request method: `getattr(self, "post")`."""
    return (
        caller.qualname == f"{DJANGO_VIEW}.dispatch"
        and callee.name in HTTP_METHODS
        and callee.cls is not None
        and (callee.cls == DJANGO_VIEW or callee.cls in index.subclasses(DJANGO_VIEW))
    )


RULES: dict[str, Rule] = {
    "pillow_open_registry": _pillow_open,
    "pillow_save_registry": _pillow_save,
    "django_view_dispatch": _django_view_dispatch,
}
_SAME_OBJECT = frozenset({"django_view_dispatch"})  # rules that call a method of `self`
_DISPATCHERS = {
    "PIL.Image.open": "factory(",
    "PIL.Image.Image.save": "save_handler(",
    f"{DJANGO_VIEW}.dispatch": "request.method",
}


def _dispatch_line(caller: Scope, index: CodeIndex, marker: str) -> int:
    code = index.code(caller.module)
    if code is not None:
        for number in range(caller.start, caller.end + 1):
            if marker in code.lines[number - 1]:
                return number
    return caller.start


def registry_edges(index: CodeIndex) -> dict[str, list[tuple[Scope, int, str]]]:
    """Dispatch edges for the path search, keyed by the callee they reach."""
    edges: dict[str, list[tuple[Scope, int, str]]] = {}
    callees: list[Scope] = []
    for module in sorted(index.reach.reached):
        code = index.code(module)
        if code is None:
            continue
        if module.startswith("PIL."):
            callees += [s for s in code.scopes.values() if s.kind == "function"]
        else:
            callees += [s for s in code.scopes.values() if s.name in HTTP_METHODS and s.cls]
    for route in [*admin_upload_routes(index), *admin_login_routes(index)]:
        caller, callee = index.scope(route.caller), index.scope(route.callee)
        if caller is None or callee is None:
            continue
        index.rule_edges[(caller.qualname, route.line, callee.qualname)] = (route.rule, route.note)
        edges.setdefault(callee.qualname, []).append((caller, route.line, route.rule))
    for caller_name, marker in _DISPATCHERS.items():
        caller = index.scope(caller_name)
        if caller is None or not index.reach.is_reached(caller.module):
            continue
        line = _dispatch_line(caller, index, marker)
        for callee in callees:
            for name, rule in RULES.items():
                if rule(caller, callee, index):
                    edges.setdefault(callee.qualname, []).append((caller, line, name))
    return edges


# -- verification -------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Hop:
    via: str
    certain: bool
    self_type: str | None  # concrete class of `self` in the callee, when the path shows it


def _edge(
    caller: Scope, line: int, callee: Scope, index: CodeIndex, self_type: str | None
) -> _Hop | str:
    """How `caller` reaches `callee` at `line`, or the reason it does not."""
    if not caller.start <= line <= caller.end:
        return f"line {line} is outside {caller.qualname}"
    route = index.rule_edges.get((caller.qualname, line, callee.qualname))
    if route is not None:
        return _Hop(route[0], True, None)
    best: _Hop | None = None
    for site in caller.sites:
        if site.line != line:
            continue
        how = index.edge(callee, site, caller)
        if how is None:
            continue
        if (
            site.recv == "self"
            and self_type
            and callee.cls
            and not index.dispatches_to(self_type, callee, exact=True)
        ):
            continue  # self is exactly a `self_type`: only the method its class resolves to
        hop = _Hop(site.kind, how == "certain", _next_self_type(site, callee, self_type, index))
        if best is None or (hop.certain and not best.certain):
            best = hop
    if best is not None:
        return best
    ruled = _rule_hop(caller, callee, index, self_type)
    if ruled is not None:
        return ruled
    if self_type:
        return (
            f"line {line} of {caller.qualname} does not reach {callee.qualname} when self is "
            f"a {self_type}"
        )
    return f"line {line} of {caller.qualname} does not call or refer to {callee.qualname}"


def _rule_hop(caller: Scope, callee: Scope, index: CodeIndex, self_type: str | None) -> _Hop | None:
    """A dispatch rule that connects `caller` to `callee`, if any."""
    for name, rule in RULES.items():
        if not rule(caller, callee, index):
            continue
        if name not in _SAME_OBJECT:
            return _Hop(name, True, None)
        if self_type and callee.cls and not index.dispatches_to(self_type, callee, exact=True):
            continue  # the handler must be the one the class of `self` resolves to
        return _Hop(name, True, self_type)
    return None


def _next_self_type(
    site: Site, callee: Scope, self_type: str | None, index: CodeIndex
) -> str | None:
    """The concrete class of `self` inside `callee`, if this hop shows it."""
    if callee.name in {"__init__", "__new__"} and site.kind == "call" and site.recv != "super":
        built = index.resolve(site.ref) if site.ref else ""
        return built if index.is_class(built) else None  # instantiating that class
    if site.kind == "string" and callee.name in {"__init__", "__call__"}:
        named = index.resolve(site.name)
        return named if index.is_class(named) else None  # the class a setting names
    if site.recv in {"self", "super"}:
        return self_type
    if site.recv.startswith("@"):
        known = index.resolve(site.recv[1:])
        return known if index.is_class(known) else None
    if site.recv.startswith("%") and site.ref:
        owner = index.resolve(site.ref.rsplit(".", 1)[0])
        return owner if index.is_class(owner) else None  # Class.classmethod(): cls is Class
    return None


def verify_path(
    steps: Sequence[Step], target: str, index: CodeIndex
) -> VerifiedPath | PathRejected:
    reasons: list[str] = []
    if not steps:
        return PathRejected(("the path is empty",))
    if len(steps) > MAX_HOPS:
        return PathRejected((f"the path has more than {MAX_HOPS} steps",))
    if steps[-1].symbol != target:
        reasons.append(f"the path must end at {target}")
    symbols = [s.symbol for s in steps]
    if len(set(symbols)) != len(symbols):
        reasons.append("the path visits the same step twice")
    scopes: list[Scope] = []
    for step in steps:
        scope = index.scope(step.symbol)
        if scope is None:
            reasons.append(f"{step.symbol} is not a known function or module")
        elif not index.reach.is_reached(scope.module):
            reasons.append(f"{step.symbol} is in {scope.module}, which the project never loads")
        else:
            scopes.append(scope)
    if reasons:
        return PathRejected(tuple(reasons))
    if scopes[0].module not in index.reach.project_modules:
        return PathRejected(
            (f"the path must start in the project's own code, not {scopes[0].qualname}",)
        )
    walked = _walk(scopes, steps, index)
    if isinstance(walked, PathRejected):
        return walked
    lines, hops = walked
    return VerifiedPath(
        tuple(
            Hop(
                file=index.reach.modules[scope.module].rel,
                line=lines[i] if i < len(scopes) - 1 else scope.start,
                symbol=scope.qualname,
                via=hops[i].via,
                certain=hops[i].certain,
            )
            for i, scope in enumerate(scopes)
        )
    )


MAX_ALTERNATIVES = 12  # other lines tried per step
MAX_ATTEMPTS = 400  # edge checks per verification


def _walk(
    scopes: list[Scope], steps: Sequence[Step], index: CodeIndex
) -> tuple[list[int], list[_Hop]] | PathRejected:
    """Check every hop, trying other lines of a step when the cited one leads to a type conflict.

    A step can mention the next one on several lines (seven middleware classes in one settings
    list); the line decides the class of `self` further on. The cited line is tried first.
    """
    budget = [MAX_ATTEMPTS]
    first_failure: list[PathRejected] = []

    def alternatives(i: int) -> list[int]:
        cited = steps[i].line
        others = sorted(
            {
                site.line
                for site in scopes[i].sites
                if site.line != cited and index.edge(scopes[i + 1], site, scopes[i]) is not None
            }
        )
        return [cited, *others[:MAX_ALTERNATIVES]]

    def go(
        i: int, self_type: str | None, typed_at: str | None
    ) -> tuple[list[int], list[_Hop]] | None:
        if i == len(scopes) - 1:
            return [], [_Hop("start", True, None)]
        for line in alternatives(i):
            if budget[0] <= 0:
                return None
            budget[0] -= 1
            result = _edge(scopes[i], line, scopes[i + 1], index, self_type)
            if isinstance(result, str):
                if not first_failure:
                    first_failure.append(
                        PathRejected((result,), blame=typed_at or scopes[i].qualname)
                    )
                continue
            changed = result.self_type != self_type
            rest = go(
                i + 1,
                result.self_type,
                (scopes[i].qualname if result.self_type else None) if changed else typed_at,
            )
            if rest is not None:
                lines, hops = rest
                return [line, *lines], [hops[0], result, *hops[1:]]
        return None

    found = go(0, None, None)
    if found is None:
        return first_failure[0] if first_failure else PathRejected(("no hop could be checked",))
    return found


# -- search -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SearchResult:
    path: VerifiedPath | None
    rejected: tuple[str, ...]  # why earlier candidates failed verification


def find_path(
    target: Scope,
    index: CodeIndex,
    extra: dict[str, list[tuple[Scope, int, str]]],
    *,
    avoid: set[str] | None = None,
    through: Sequence[str] = (),
    certain_only: bool = False,
    trusted: set[tuple[str, int, str]] | None = None,
) -> SearchResult:
    """Cheapest verified path to `target`, optionally via the `through` steps in order.

    Searches, verifies, and searches again around the step a failed verification blames.
    """
    waypoints: list[Scope] = []
    for name in through:
        scope = index.scope(name)
        if scope is None or not index.reach.is_reached(scope.module):
            return SearchResult(None, (f"{name} is not a known function in loaded code",))
        waypoints.append(scope)
    avoided = set(avoid or set())
    rejected: list[str] = []
    for _ in range(MAX_SEARCHES):
        found = _search(
            target,
            waypoints,
            index=index,
            extra=extra,
            avoid=avoided,
            certain_only=certain_only,
            trusted=trusted,
        )
        if found is None:
            break
        result = verify_path(
            [Step(s.qualname, line) for s, line, _ in found], target.qualname, index
        )
        if isinstance(result, VerifiedPath):
            return SearchResult(result, tuple(rejected))
        rejected.append("; ".join(result.reasons))
        blame = result.blame or found[0][0].qualname
        if blame in {w.qualname for w in waypoints} or blame in avoided:
            break
        avoided.add(blame)
    return SearchResult(None, tuple(rejected))


def _search(
    target: Scope,
    waypoints: list[Scope],
    *,
    index: CodeIndex,
    extra: dict[str, list[tuple[Scope, int, str]]],
    avoid: set[str],
    certain_only: bool,
    trusted: set[tuple[str, int, str]] | None = None,
) -> list[tuple[Scope, int, str]] | None:
    """Project -> waypoint 1 -> ... -> target, each leg the cheapest available."""
    stops = [*waypoints, target]
    path: list[tuple[Scope, int, str]] = []
    for i, stop in enumerate(stops):
        if i == 0 and stop is not target and stop.module in index.reach.project_modules:
            path = [(stop, stop.start, "")]  # the route starts at this project function
            continue
        start_at = {stops[i - 1].qualname} if i else None
        leg = index.shortest_path(
            stop,
            extra,
            certain_only=certain_only,
            start_at=start_at,
            avoid=avoid,
            trusted=trusted,
        )
        if leg is None:
            return None
        path = [*path[:-1], *leg] if path else leg
    return path
