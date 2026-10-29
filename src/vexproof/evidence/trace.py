"""Find a call path to each verified vulnerable function; the model reviews the uncertain hops.

1. A deterministic search finds the cheapest path from project code to the function (paths
   made only of certain hops first), and the verifier checks it hop by hop (`paths.py`). No
   path: done, no model call.
2. Every hop certain: accepted without a model.
3. Otherwise Muse Spark reviews it in a short loop: accept (saying why each uncertain hop is
   plausible), search again around a wrong hop (`avoid`) or along a known route (`through`), or
   look at `callers` and `source`. Whatever path it accepts is verified again; the model can
   steer the search, never invent a hop.

Requests depend only on the target and the evidence shown, never on the advisory, so findings
that share a vulnerable function share answers, and recordings replay across runs.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from vexproof.evidence.paths import (
    SearchResult,
    Step,
    VerifiedPath,
    find_path,
    route_notes,
    verify_path,
)
from vexproof.llm.structured import StructuredCaller
from vexproof.llm.types import BudgetExceededError, ModelError
from vexproof.prompts import load_prompt
from vexproof.static.codeindex import CodeIndex, Scope

PROMPT_VERSION = "trace_path.v3"
PURPOSE = "trace_path"
MAX_STEPS = 12
MAX_OUTPUT_TOKENS = 4096
_RECENT = 3  # observations shown in full; older ones are shortened
_LIST = 25


class TraceAction(BaseModel):
    """One review step. Parsing is lenient about shape, never about meaning.

    Models without enforced schemas often leave out fields they consider empty, or wrap the
    arguments the way tool calls look (`{"name": "search", "arguments": {...}}`). Those shapes are
    normalised; an unknown action is still an error.
    """

    model_config = ConfigDict(extra="ignore")

    action: Literal["accept", "search", "callers", "source", "give_up"]
    avoid: list[str] = Field(
        default_factory=list, description="search: qualified names the path must not use"
    )
    through: list[str] = Field(
        default_factory=list, description="search: qualified names to pass through, in order"
    )
    symbol: str = Field(default="", description="callers/source: a qualified name; else empty")
    reason: str = Field(
        default="", description="one or two sentences; for accept, why each POSSIBLE hop holds"
    )

    @model_validator(mode="before")
    @classmethod
    def _normalise(cls, data: object) -> object:
        return _tidy(_unwrap(data)) if isinstance(data, dict) else data


_WRAPPERS = ("arguments", "args", "parameters", "params", "input")
_ALIASES = {
    "action": (
        "reply",
        "decision",
        "choice",
        "verb",
        "tool",
        "name",
        "next_action",
        "type",
        "step",
    ),
    "symbol": ("target", "function", "qualname", "qualified_name"),
    "reason": ("rationale", "explanation", "why"),
}


# What models say instead of the five actions, seen with Muse Spark Open and close variants.
_SYNONYMS = {
    **dict.fromkeys(
        ["avoid", "search_again", "re_search", "research", "retry", "reroute", "route",
         "alternative", "find_path", "new_path", "reject_hop"],
        "search",
    ),
    **dict.fromkeys(["approve", "confirm", "plausible", "accept_path", "yes"], "accept"),
    **dict.fromkeys(["reject", "giveup", "stop", "no_path", "none", "unreachable"], "give_up"),
    **dict.fromkeys(["find_callers", "who_calls", "list_callers", "caller"], "callers"),
    **dict.fromkeys(["read", "show", "show_source", "view", "inspect", "code"], "source"),
}  # fmt: skip


def _unwrap(data: dict[str, object]) -> dict[str, object]:
    """`{"TraceAction": {...}}` and `{"name": ..., "arguments": {...}}` -> one flat object."""
    if "action" not in data and len(data) == 1:
        (only,) = data.values()
        if isinstance(only, dict):
            data = only
    flat = dict(data)
    for key in _WRAPPERS:
        inner = flat.pop(key, None)
        if isinstance(inner, dict):
            flat = {**inner, **flat}
    for field, aliases in _ALIASES.items():
        if field not in flat:
            found = next((flat[a] for a in aliases if isinstance(flat.get(a), str)), None)
            if found is not None:
                flat[field] = found
    return flat


def _tidy(data: dict[str, object]) -> dict[str, object]:
    """ "Give Up" -> "give_up"; a string for a list -> a list; null -> the default."""
    action = data.get("action")
    if isinstance(action, str):
        word = action.strip().lower().replace(" ", "_").replace("-", "_")
        data["action"] = _SYNONYMS.get(word, word)
    for field in ("avoid", "through"):
        value = data.get(field)
        if isinstance(value, str):
            data[field] = [value] if value else []
        elif value is None:
            data.pop(field, None)
    for field in ("symbol", "reason"):
        if data.get(field) is None:
            data.pop(field, None)
    return data


@dataclass(frozen=True)
class TraceOutcome:
    path: VerifiedPath | None
    reviewed: bool  # a model judged the uncertain hops
    note: str
    candidate: VerifiedPath | None = None  # an unreviewed path, when no model was available


class Tracer:
    """Traces vulnerable functions; one result per function, shared by every finding."""

    def __init__(
        self,
        index: CodeIndex,
        extra: dict[str, list[tuple[Scope, int, str]]],
        caller: StructuredCaller | None,
    ) -> None:
        self._index = index
        self._extra = extra
        self._caller = caller
        self._done: dict[str, TraceOutcome] = {}
        # uncertain hops (caller, line, callee) the model judged plausible, and why
        self._approved: dict[tuple[str, int, str], str] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()

    def trace(self, qualname: str) -> TraceOutcome:
        with self._guard:
            lock = self._locks.setdefault(qualname, threading.Lock())
        with lock:
            if qualname not in self._done:
                self._done[qualname] = self._trace(qualname)
            return self._done[qualname]

    def _trace(self, qualname: str) -> TraceOutcome:
        target = self._index.scope(qualname)
        if target is None or not self._index.reach.is_reached(target.module):
            return TraceOutcome(None, False, f"{qualname} was not found in the loaded code")
        # a path of certain hops is the best evidence: look for one before allowing others
        first = find_path(target, self._index, self._extra, certain_only=True)
        if first.path is None:
            first = find_path(target, self._index, self._extra, trusted=set(self._approved))
        if first.path is None:
            return TraceOutcome(
                None, False, "no call path from your code was found (searched by name)"
            )
        if first.path.possible_hops == 0:
            routes = route_notes(first.path, self._index)
            note = "every hop of the path is certain" + "".join(f"; {r}" for r in routes)
            return TraceOutcome(first.path, False, note)
        open_hops = _uncertain(first.path) - set(self._approved)
        if not open_hops:
            reasons = dict.fromkeys(self._approved[h] for h in _uncertain(first.path))
            return TraceOutcome(
                first.path,
                True,
                "its uncertain hops were judged plausible in an earlier review: "
                + " | ".join(reasons),
            )
        if self._caller is None:
            return TraceOutcome(
                None,
                False,
                f"a path with {first.path.possible_hops} uncertain hop(s) exists; "
                "a model must review it before it counts",
                candidate=first.path,
            )
        return self._review(target, first)

    # -- the review loop ----------------------------------------------------------------------

    def _review(self, target: Scope, first: SearchResult) -> TraceOutcome:
        assert self._caller is not None  # noqa: S101 - checked by _trace
        current: VerifiedPath | None = first.path
        history: list[tuple[str, str]] = []
        avoided: set[str] = set()  # accumulates: the model need not repeat earlier entries
        system = load_prompt(PROMPT_VERSION)
        for _ in range(MAX_STEPS):
            user = self._render(target, current, history)
            try:
                act = self._caller.ask(
                    TraceAction,
                    purpose=PURPOSE,
                    prompt_version=PROMPT_VERSION,
                    system=system,
                    user=user,
                    max_output_tokens=MAX_OUTPUT_TOKENS,
                )
            except BudgetExceededError:
                raise
            except ModelError as exc:
                return TraceOutcome(None, False, f"path review failed: {exc}", candidate=current)
            if act.action == "accept":
                if current is None:
                    history.append((_describe(act), "there is no current path to accept"))
                    continue
                again = verify_path(
                    [Step(h.symbol, h.line) for h in current.hops], target.qualname, self._index
                )
                if isinstance(again, VerifiedPath):
                    for hop in _uncertain(again):
                        self._approved.setdefault(hop, act.reason.strip()[:300])
                    return TraceOutcome(again, True, act.reason.strip())
                history.append((_describe(act), "the path no longer verifies"))
            elif act.action == "give_up":
                return TraceOutcome(
                    None, True, f"model found no plausible path: {act.reason.strip()}", current
                )
            elif act.action == "search":
                result = find_path(
                    target,
                    self._index,
                    self._extra,
                    avoid=(avoided := avoided | _avoid(act.avoid, target, current)),
                    through=[t for t in act.through if t != target.qualname],
                    trusted=set(self._approved),
                )
                current = result.path
                observation = (
                    "new candidate path shown above"
                    if result.path
                    else "no verified path with those constraints"
                    + (f" ({result.rejected[-1]})" if result.rejected else "")
                )
                history.append((_describe(act), observation))
            elif act.action == "callers":
                history.append((_describe(act), self._callers(act.symbol)))
            else:
                source = self._index.source(act.symbol)
                history.append(
                    (_describe(act), f"<code>\n{source}\n</code>" if source else "unknown function")
                )
        return TraceOutcome(
            None, True, f"model accepted no path within {MAX_STEPS} steps", candidate=current
        )

    def _callers(self, symbol: str) -> str:
        scope = self._index.scope(symbol)
        if scope is None:
            return "unknown function: use a qualified name shown earlier"
        found = self._index.callers(scope)
        if not found:
            return "no mentions in loaded code"
        project = self._index.reach.project_modules
        found.sort(key=lambda item: (item[2] != "certain", item[0].module not in project))
        lines = [
            f"{how:8} {s.qualname} line {site.line}: {self._index.line(s.module, site.line)[:100]}"
            for s, site, how in found[:_LIST]
        ]
        more = len(found) - _LIST
        return (
            "<code>\n" + "\n".join(lines) + "\n</code>" + (f"\n... {more} more" if more > 0 else "")
        )

    def _render(
        self, target: Scope, current: VerifiedPath | None, history: list[tuple[str, str]]
    ) -> str:
        reach = self._index.reach
        parts = [
            f"Target: {target.qualname}",
            f"Its module is loaded because: {reach.why(target.module, limit=3)}",
            "Project modules: " + ", ".join(sorted(reach.project_modules)[:40]),
            "",
        ]
        if current is None:
            parts.append("There is no current candidate path.")
        else:
            parts += ["Current candidate path (verified hop by hop):", "<code>"]
            approved = self._approved
            for i, hop in enumerate(current.hops):
                mark = "start" if i == 0 else ("certain" if hop.certain else "POSSIBLE")
                if mark == "POSSIBLE" and (
                    (current.hops[i - 1].symbol, current.hops[i - 1].line, hop.symbol) in approved
                ):
                    mark = "reviewed"
                code = self._index.line(self._index.module_of(hop.symbol) or "", hop.line)
                parts.append(f"{i:>2} {mark:8} {hop.symbol}  [{hop.file}:{hop.line}]  {code[:100]}")
            parts.append("</code>")
        if history:
            parts += ["", "Your earlier steps:"]
            for i, (action, observation) in enumerate(history):
                recent = i >= len(history) - _RECENT
                shown = observation if recent else observation[:200] + " ..."
                parts.append(f"- {action}\n{shown}")
        parts += ["", "Choose the next action."]
        return "\n".join(parts)


def _describe(act: TraceAction) -> str:
    if act.action == "search":
        return f"search(avoid+={act.avoid}, through={act.through})"
    if act.action in {"callers", "source"}:
        return f"{act.action}({act.symbol})"
    return act.action


def _avoid(names: list[str], target: Scope, current: VerifiedPath | None) -> set[str]:
    """The steps to avoid. Avoiding the target itself means "not this way in": its caller."""
    avoided = set(names) - {target.qualname}
    if target.qualname in names and current is not None and current.hops[:-1]:
        avoided.add(current.hops[-2].symbol)
    return avoided


def _uncertain(path: VerifiedPath) -> set[tuple[str, int, str]]:
    """The path's uncertain hops as (caller, line where it calls, callee)."""
    hops = path.hops
    return {
        (hops[i - 1].symbol, hops[i - 1].line, hops[i].symbol)
        for i in range(1, len(hops))
        if not hops[i].certain
    }
