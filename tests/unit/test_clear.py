from __future__ import annotations

from pathlib import Path

import pytest

from tests.codebase import build
from vexproof.domain import Advisory, Candidate, Evidence, Finding, Level, Package, Verdict
from vexproof.evidence.clear import MODULE_NOT_LOADED, clear_by_module
from vexproof.static.modules import ModuleReach


@pytest.fixture
def reach(tmp_path: Path) -> ModuleReach:
    return build(tmp_path)[0]


def _candidate(qualname: str) -> Candidate:
    module = qualname.rsplit(".", 1)[0]
    return Candidate(qualname=qualname, module=module, file="f.py", changed_lines=1)


def _finding(evidence: Evidence, verdict: Verdict | None = None) -> Finding:
    return Finding(
        id="pillow@9.0.0:GHSA-x",
        package=Package(name="pillow", version="9.0.0"),
        advisory=Advisory(id="GHSA-x"),
        evidence=evidence,
        verdict=verdict,
    )


MATH = _candidate("PIL.ImageMath.eval")
COLOR = _candidate("PIL.ImageColor.getrgb")


def test_unloaded_module_clears(reach: ModuleReach) -> None:
    cleared = clear_by_module(_finding(Evidence(level=Level.L1_SYMBOL, candidates=(MATH,))), reach)
    assert cleared.verdict is Verdict.NOT_AFFECTED
    assert cleared.justification == "vulnerable_code_not_in_execute_path"
    assert cleared.evidence is not None
    assert MODULE_NOT_LOADED in cleared.evidence.checks_passed
    assert cleared.evidence.notes[-1].startswith("never loaded by your code: PIL.ImageMath")


def test_a_pick_never_narrows_a_clear(reach: ModuleReach) -> None:
    # ADR 0020: the verified pick is in unloaded ImageMath, but the fix also changes ImageColor,
    # which is loaded. Every changed module counts, so the pick cannot clear the alert.
    picked = Evidence(
        level=Level.L1_SYMBOL,
        candidates=(MATH, COLOR),
        vulnerable_symbols=(MATH.qualname,),
        symbol_model="m",
    )
    held = clear_by_module(_finding(picked), reach)
    assert held.verdict is None
    assert held.evidence is not None
    assert held.evidence.notes[-1].startswith("module loaded by your code: PIL.ImageColor")
    # the same with no pick at all: the outcome does not depend on the model
    unpicked = clear_by_module(
        _finding(Evidence(level=Level.L1_SYMBOL, candidates=(MATH, COLOR))), reach
    )
    assert unpicked.verdict is None
    assert unpicked.evidence == held.evidence.model_copy(
        update={"vulnerable_symbols": (), "symbol_model": None}
    )
    # module-level changes count too, even when the pick's module is unloaded
    with_module_change = picked.model_copy(
        update={"candidates": (MATH,), "changed_modules": ("PIL.ImageColor",)}
    )
    assert clear_by_module(_finding(with_module_change), reach).verdict is None


def test_a_pick_does_not_block_a_clear_when_every_changed_module_is_unloaded(
    reach: ModuleReach,
) -> None:
    picked = Evidence(
        level=Level.L1_SYMBOL,
        candidates=(MATH,),
        vulnerable_symbols=(MATH.qualname,),
        symbol_model="m",
    )
    cleared = clear_by_module(_finding(picked), reach)
    assert cleared.verdict is Verdict.NOT_AFFECTED
    assert cleared.evidence is not None
    assert MODULE_NOT_LOADED in cleared.evidence.checks_passed


def test_never_cleared_here(reach: ModuleReach) -> None:
    none_match = Evidence(level=Level.L1_SYMBOL, candidates=(MATH,), symbol_model="m")
    assert clear_by_module(_finding(none_match), reach).verdict is None
    native = Evidence(level=Level.L1_SYMBOL, candidates=(MATH,), native_changes=("src/math.c",))
    held = clear_by_module(_finding(native), reach)
    assert held.verdict is None
    assert held.evidence is not None
    assert "compiled code (src/math.c)" in held.evidence.notes[-1]
    l3 = Evidence(level=Level.L3_NONE)
    assert clear_by_module(_finding(l3), reach).verdict is None
    decided = _finding(Evidence(level=Level.L1_SYMBOL, candidates=(MATH,)), Verdict.AFFECTED)
    assert clear_by_module(decided, reach) is decided
    bare = _finding(Evidence(level=Level.L1_SYMBOL)).model_copy(update={"evidence": None})
    assert clear_by_module(bare, reach) is bare


def test_module_level_changes_and_blockers(reach: ModuleReach) -> None:
    l2 = Evidence(level=Level.L2_MODULE, changed_modules=("PIL.ImageMath",))
    assert clear_by_module(_finding(l2), reach).verdict is Verdict.NOT_AFFECTED
    reach.blockers.append("something loads code by computed name")
    held = clear_by_module(_finding(l2), reach)
    assert held.verdict is None
    assert held.evidence is not None
    assert "not cleared because something loads code" in held.evidence.notes[-1]
