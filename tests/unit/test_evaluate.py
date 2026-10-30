"""The evaluation: a scan checked against what loaded and ran when the project was driven."""

from __future__ import annotations

from typing import Any

import pytest

from tests.report_fixtures import CHAIN, finding
from vexproof.domain import Candidate, Level, Verdict
from vexproof.errors import IngestError
from vexproof.evaluate.markdown import render_markdown, summary_rows
from vexproof.evaluate.score import evaluate, load_observation, load_record
from vexproof.symbols.gold import GoldCase

FRAME = CHAIN[-1].symbol


def _cleared(advisory: str, module: str) -> Any:
    f = finding(advisory, verdict=Verdict.NOT_AFFECTED)
    evidence = f.evidence.model_copy(  # type: ignore[union-attr]
        update={
            "candidates": (
                Candidate(qualname=f"{module}.fn", module=module, file="x.py", changed_lines=1),
            )
        }
    )
    return f.model_copy(update={"evidence": evidence})


def _findings() -> list[Any]:
    package_level = finding("GHSA-l0", verdict=Verdict.NOT_AFFECTED, level=Level.L0_NOT_IMPORTED)
    return [
        _cleared("GHSA-ok", "PIL.ImageMath"),
        _cleared("GHSA-bad", "PIL.GifImagePlugin"),
        package_level,
        finding("GHSA-ran", verdict=Verdict.AFFECTED),
        finding("GHSA-idle", verdict=Verdict.AFFECTED).model_copy(
            update={
                "evidence": finding("x", verdict=Verdict.AFFECTED).evidence.model_copy(  # type: ignore[union-attr]
                    update={
                        "call_chain": (
                            *CHAIN[:-1],
                            CHAIN[-1].model_copy(
                                update={"symbol": "PIL.FpxImagePlugin.FpxImageFile._open_index"}
                            ),
                        )
                    }
                )
            }
        ),
        finding("GHSA-missed", picks=("PIL.Image.open",)),
        finding("GHSA-open"),
    ]


def _record(**extra: Any) -> Any:
    return load_record(
        {
            "source": "https://github.com/acme/shop",
            "commit": "1aa90f67f4559a36d8049d8a2d3fe622791ee95c",
            "findings": [f.model_dump(mode="json") for f in _findings()],
            "closure": {
                "reached": ["PIL", "PIL.Image", "PIL.GifImagePlugin", "shop", "shop.admin"],
                "unreached": ["PIL.ImageMath", "PIL.TarIO"],
                "blockers": [],
            },
            "model": {"cost_usd": 0.47, "calls": 12},
            "timings_s": {"intel": 2.0, "prove": 30.0},
            "summary": {"ignored": True},
            **extra,
        }
    )


def _observation(**changes: Any) -> Any:
    data = {
        "project": "/x",
        "workload": "shop.py",
        "python": "3.8.20",
        "packages": {"django": "2.0", "pillow": "4.3.0", "pytz": "2017.3"},
        "seconds": 4.2,
        "steps": [{"step": "home", "status": 200}],
        "loaded_modules": [
            "PIL",
            "PIL.Image",
            "PIL.GifImagePlugin",
            "PIL._imaging",
            "shop",
            "shop.admin",
            "json",
            "os",
        ],
        "executed_functions": [FRAME, "PIL.Image.open", "shop.views.home"],
    }
    data.update(changes)
    return load_observation(data)


def test_clears_paths_and_misses() -> None:
    result = evaluate(_record(), _observation())
    clears = {c.finding.advisory.id: c for c in result.clears}
    assert clears["GHSA-ok"].status == "consistent"
    assert clears["GHSA-bad"].status == "falsified"
    assert clears["GHSA-bad"].loaded == ("PIL.GifImagePlugin",)
    assert clears["GHSA-l0"].status == "uncheckable"
    paths = {p.finding.advisory.id: p.status for p in result.paths}
    assert paths == {"GHSA-ran": "confirmed", "GHSA-idle": "not_exercised"}
    assert [f.advisory.id for f in result.executed_open] == ["GHSA-missed"]
    assert (result.alerts, result.decided, result.open) == (7, 5, 2)
    assert result.sound is False  # one clear contradicted
    assert result.cost_usd == 0.47
    assert result.scan_seconds == 32.0


def test_closure_soundness() -> None:
    result = evaluate(_record(), _observation())
    closure = result.closure
    assert closure is not None
    assert closure.missed == ()
    assert closure.not_in_source == ("PIL._imaging",)  # compiled, no source to scan
    assert closure.loaded == 5  # json and os are outside the scanned packages
    assert closure.reached_not_loaded == 0
    gap = _observation(loaded_modules=["PIL", "PIL.TarIO"])
    missed = evaluate(_record(), gap)
    assert missed.closure is not None
    assert missed.closure.missed == ("PIL.TarIO",)
    assert missed.sound is False
    no_closure = evaluate(_record(closure=None), _observation(loaded_modules=["shop"]))
    assert no_closure.closure is None
    assert no_closure.sound is True


def test_gold_checks_read_picks_and_none_matches() -> None:
    cases = (
        GoldCase(advisory="GHSA-ran", package="pillow", expected=(FRAME,), why="w"),
        GoldCase(advisory="GHSA-missed", package="pillow", expected=("PIL.Other.f",), why="w"),
        GoldCase(advisory="GHSA-none", package="pillow", expected="none", why="w"),
        GoldCase(advisory="GHSA-silent", package="pillow", expected="none", why="w"),
        GoldCase(advisory="GHSA-absent", package="pillow", expected="none", why="w"),
    )
    none = finding("GHSA-none", notes=("none of the changed functions matches the advisory",))
    silent = finding("GHSA-silent")  # the model was never asked
    record = _record(findings=[f.model_dump(mode="json") for f in (*_findings(), none, silent)])
    missed = finding("GHSA-missed", picks=("PIL.Image.open",), model="m")
    record = record.model_copy(
        update={
            "findings": tuple(
                missed if f.advisory.id == "GHSA-missed" else f for f in record.findings
            )
        }
    )
    gold = {g.case.advisory: g.correct for g in evaluate(record, _observation(), cases).gold}
    assert gold == {"GHSA-ran": True, "GHSA-missed": False, "GHSA-none": True}


def test_markdown_and_summary() -> None:
    result = evaluate(_record(), _observation())
    rows = dict(summary_rows(result))
    assert rows["Decided with evidence"] == "5 (71.4%): 3 cleared, 2 reachable"
    assert rows["Clears contradicted by the run (module loaded)"] == (
        "1 of 2 (1 package-level, checked via the closure)"
    )
    assert rows["Reachable alerts whose vulnerable function ran"] == (
        "1 of 2 (1 not exercised by the workload)"
    )
    assert rows["Model cost of this scan (replayed answers not counted)"] == (
        "$0.4700 total, $0.06714 per alert"
    )
    fresh = evaluate(_record(model={"cost_usd": 0.01, "fresh_cost_usd": 0.7}), _observation())
    assert fresh.cost_is_fresh
    assert dict(summary_rows(fresh))["Model cost of a scan without recordings"] == (
        "$0.7000 total, $0.10000 per alert"
    )
    text = render_markdown(result)
    assert text.startswith("# Evaluation: https://github.com/acme/shop @ `1aa90f67f455`")
    assert "**Verdict: UNSOUND**" in text
    assert "with django 2.0, pillow 4.3.0" in text
    assert "pytz" not in text
    assert "| GHSA-bad | `PIL.GifImagePlugin` | **yes: wrong clear** (PIL.GifImagePlugin) |" in text
    assert "| GHSA-l0 | (package) | checked via the closure |" in text
    assert f"| GHSA-ran | `{FRAME}` | yes |" in text
    assert "- `PIL._imaging` (no Python source file: a compiled extension" in text
    assert "- GHSA-missed: `PIL.Image.open`" in text


def test_markdown_when_sound_and_minimal() -> None:
    record = load_record({"findings": [_findings()[0].model_dump(mode="json")]})
    result = evaluate(record, _observation())
    text = render_markdown(result)
    assert "**Verdict: sound**" in text
    assert "Model cost" not in text
    assert "Scan time" not in text
    assert "## Open alerts whose picked function ran" not in text
    assert summary_rows(result)[2] == ("Clears contradicted by the run (module loaded)", "0 of 1")


@pytest.mark.parametrize(
    ("loader", "data", "message"),
    [
        (load_record, {"findings": "nope"}, "not a findings file"),
        (load_observation, {"workload": "w"}, "not an observation file"),
    ],
)
def test_bad_inputs(loader: Any, data: dict[str, Any], message: str) -> None:
    with pytest.raises(IngestError, match=message):
        loader(data)
