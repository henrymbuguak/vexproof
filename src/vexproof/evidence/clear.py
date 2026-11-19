"""Clear an alert when no module its fix changes is ever loaded.

The modules that decide a clear are every module the fix changes: those of every changed
function and of every module-level change, taken from the fix commits the advisory references.
A model may block a clear but never enable or narrow one (ADR 0020):
- verified picks do not narrow the set; they only steer the call-path search;
- the model said none of the changed functions matches the advisory: never cleared here, since
  the vulnerable code may lie outside the changed functions.

Never cleared when the fix also changes compiled code in the package (C sources can run without
any Python module naming them), or when module reach has blockers.

ADR 0022: when the only blockers are library computed imports that pass a module name in, the
alert can be an *assumed clear*. It stays open, carries the check
`module_not_loaded_assuming_configuration` and the imports it rests on, and only a person
approving it may make it `not_affected`.
"""

from __future__ import annotations

from vexproof.domain import ASSUMED_CLEAR_CHECK, Finding, Level, Verdict
from vexproof.static.levels import NOT_IN_EXECUTE_PATH
from vexproof.static.modules import ModuleReach

MODULE_NOT_LOADED = "module_not_loaded"
MODULE_NOT_LOADED_ASSUMING = ASSUMED_CLEAR_CHECK  # ADR 0022
_SITES_SHOWN = 3  # computed imports named in an assumed clear's note; the evidence keeps all


def relevant_modules(finding: Finding) -> set[str] | None:
    """The modules whose loading decides this alert, or None if it cannot be decided here.

    Every module the fix changes, whatever the model picked: a pick never narrows the set.
    """
    evidence = finding.evidence
    if evidence is None or evidence.level not in {Level.L1_SYMBOL, Level.L2_MODULE}:
        return None
    if evidence.symbol_model and not evidence.vulnerable_symbols:
        return None  # the model looked and found no matching changed function: blocks the clear
    return {c.module for c in evidence.candidates} | set(evidence.changed_modules)


def clear_by_module(finding: Finding, reach: ModuleReach) -> Finding:
    evidence = finding.evidence
    if evidence is None or finding.verdict is not None:
        return finding
    modules = relevant_modules(finding)
    if not modules:
        return finding
    loaded = sorted(m for m in modules if reach.is_reached(m))
    if loaded:
        note = f"module loaded by your code: {reach.why(loaded[0], limit=3)}"
        return _with(finding, notes=(*evidence.notes, note))
    shown = ", ".join(sorted(modules)[:4])
    if reach.blockers:
        note = f"never loaded by your code: {shown}; not cleared because {reach.blockers[0]}"
        assumed = _assumed_clear(finding, reach, modules, shown)
        return assumed or _with(finding, notes=(*evidence.notes, note))
    if evidence.native_changes:
        files = ", ".join(evidence.native_changes[:3])
        note = (
            f"never loaded by your code: {shown}; not cleared because the fix also changes "
            f"compiled code ({files})"
        )
        return _with(finding, notes=(*evidence.notes, note))
    updated = evidence.model_copy(
        update={
            "checks_passed": (*evidence.checks_passed, MODULE_NOT_LOADED),
            "notes": (
                *evidence.notes,
                f"never loaded by your code: {shown} (nothing your code loads imports it, names "
                "it in a string, or loads it through a framework rule)",
            ),
        }
    )
    return finding.model_copy(
        update={
            "verdict": Verdict.NOT_AFFECTED,
            "justification": NOT_IN_EXECUTE_PATH,
            "evidence": updated,
        }
    )


ASSUMPTION = (
    "configuration names no module beyond those written in the code and repository files, and "
    "every package installed at run time was scanned"
)


def _assumed_clear(
    finding: Finding, reach: ModuleReach, modules: set[str], shown: str
) -> Finding | None:
    """An assumed clear (ADR 0022), or None when one cannot be made either.

    It stays open (`under_investigation`): only a person approving it may turn it into
    `not_affected`. Its evidence names the assumption and the computed imports it rests on.
    """
    evidence = finding.evidence
    assert evidence is not None  # noqa: S101 - checked by the caller
    # what blocked the strict clear must be exactly the library imports the assumption covers:
    # nothing else that blocks, and at least one such import recorded
    if reach.assumed_blockers or not reach.assumed_on or evidence.native_changes:
        return None
    if any(reach.is_reached_assuming(m) for m in modules):
        return None
    relied = tuple(reach.assumed_on)
    more = len(relied) - _SITES_SHOWN
    sites = ", ".join(relied[:_SITES_SHOWN]) + (f" and {more} more" if more > 0 else "")
    note = (
        f"never loaded by your code, assuming {ASSUMPTION}: {shown}. Not a strict clear: it "
        f"rests on {len(relied)} computed import(s) in libraries that pass a module name in "
        f"({sites}); open until a person approves it"
    )
    updated = evidence.model_copy(
        update={
            "checks_passed": (*evidence.checks_passed, MODULE_NOT_LOADED_ASSUMING),
            "notes": (*evidence.notes, note),
            "assumed_on": relied,
        }
    )
    return finding.model_copy(update={"evidence": updated})


def is_assumed_clear(finding: Finding) -> bool:
    """An open alert cleared only under ADR 0022's assumption, pending a person's approval."""
    return finding.assumed_clear


def _with(finding: Finding, *, notes: tuple[str, ...]) -> Finding:
    assert finding.evidence is not None  # noqa: S101 - checked by callers
    return finding.model_copy(
        update={"evidence": finding.evidence.model_copy(update={"notes": notes})}
    )
