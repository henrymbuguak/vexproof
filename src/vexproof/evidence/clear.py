"""Clear an alert when the module holding its vulnerable code is never loaded.

Which modules count depends on what is known about the alert:
- verified model picks: the modules of the picked functions;
- no picks (no model, or nothing selected yet): the modules of every changed function and of
  every module-level change in the fix;
- the model said none of the changed functions matches the advisory: never cleared here, since
  the vulnerable code may be elsewhere.

Never cleared when the fix also changes compiled code in the package (C sources can run without
any Python module naming them), or when module reach has blockers.
"""

from __future__ import annotations

from vexproof.domain import Finding, Level, Verdict
from vexproof.static.levels import NOT_IN_EXECUTE_PATH
from vexproof.static.modules import ModuleReach

MODULE_NOT_LOADED = "module_not_loaded"


def relevant_modules(finding: Finding, module_of: dict[str, str]) -> set[str] | None:
    """The modules whose loading decides this alert, or None if it cannot be decided here."""
    evidence = finding.evidence
    if evidence is None or evidence.level not in {Level.L1_SYMBOL, Level.L2_MODULE}:
        return None
    if evidence.vulnerable_symbols:
        modules = {module_of.get(s) for s in evidence.vulnerable_symbols}
        return None if None in modules else {m for m in modules if m}
    if evidence.symbol_model:  # the model looked and found no matching changed function
        return None
    return {c.module for c in evidence.candidates} | set(evidence.changed_modules)


def clear_by_module(finding: Finding, reach: ModuleReach) -> Finding:
    evidence = finding.evidence
    if evidence is None or finding.verdict is not None:
        return finding
    module_of = {c.qualname: c.module for c in evidence.candidates}
    modules = relevant_modules(finding, module_of)
    if not modules:
        return finding
    loaded = sorted(m for m in modules if reach.is_reached(m))
    if loaded:
        note = f"module loaded by your code: {reach.why(loaded[0], limit=3)}"
        return _with(finding, notes=(*evidence.notes, note))
    shown = ", ".join(sorted(modules)[:4])
    if reach.blockers:
        note = f"never loaded by your code: {shown}; not cleared because {reach.blockers[0]}"
        return _with(finding, notes=(*evidence.notes, note))
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


def _with(finding: Finding, *, notes: tuple[str, ...]) -> Finding:
    assert finding.evidence is not None  # noqa: S101 - checked by callers
    return finding.model_copy(
        update={"evidence": finding.evidence.model_copy(update={"notes": notes})}
    )
