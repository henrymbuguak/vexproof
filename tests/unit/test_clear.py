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


def test_picks_decide_which_modules_count(reach: ModuleReach) -> None:
    # COLOR's module is loaded, but the verified pick is in ImageMath: cleared
    evidence = Evidence(
        level=Level.L1_SYMBOL,
        candidates=(MATH, COLOR),
        vulnerable_symbols=(MATH.qualname,),
        symbol_model="m",
    )
    assert clear_by_module(_finding(evidence), reach).verdict is Verdict.NOT_AFFECTED
    # no picks: every candidate counts, and ImageColor is loaded
    loaded = clear_by_module(
        _finding(Evidence(level=Level.L1_SYMBOL, candidates=(MATH, COLOR))), reach
    )
    assert loaded.verdict is None
    assert loaded.evidence is not None
    assert loaded.evidence.notes[-1].startswith("module loaded by your code: PIL.ImageColor")


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
