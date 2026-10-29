from __future__ import annotations

from pathlib import Path

import pytest

from tests.llm_fakes import Reply, pick, scripted_stack
from tests.symbol_fixtures import ICNS, ICO, QUOTE, ico_finding
from vexproof.domain import Level
from vexproof.llm.factory import ModelStack
from vexproof.llm.meta import Api
from vexproof.llm.types import BudgetExceededError, ModelError
from vexproof.modelcheck import GoldReport, GoldRow, ping, run_gold
from vexproof.symbols.gold import GoldCase

ICO_CASE = GoldCase(advisory="GHSA-95q3-8gr9-gm8w", package="pillow", expected=(ICO,), why="w")
ABSENT = GoldCase(advisory="GHSA-zzzz-zzzz-zzzz", package="pillow", expected="none", why="w")


def test_ping_prefers_responses(tmp_path: Path) -> None:
    built: list[Api] = []

    def stack_for(api: Api) -> ModelStack:
        built.append(api)
        return scripted_stack([{"ok": True, "word": "VexProof "}], tmp_path)[0]

    result = ping(stack_for)
    assert (result.api, result.errors, built) == ("responses", {}, ["responses"])


def test_ping_falls_back_to_chat_then_gives_up(tmp_path: Path) -> None:
    replies: dict[str, list[Reply]] = {
        "responses": [ModelError("endpoint not found")],
        "chat": [{"ok": True, "word": "vexproof"}],
    }
    result = ping(lambda api: scripted_stack(list(replies[api]), tmp_path)[0])
    assert result.api == "chat"
    assert "endpoint not found" in result.errors["responses"]
    preferred = ping(lambda api: scripted_stack(replies[api], tmp_path)[0], prefer="chat")
    assert (preferred.api, preferred.errors) == ("chat", {})
    wrong = ping(lambda api: scripted_stack([{"ok": False, "word": "no"}], tmp_path)[0])
    assert wrong.api is None
    assert set(wrong.errors) == {"responses", "chat"}


def test_run_gold_scores_each_case(tmp_path: Path) -> None:
    stack, live = scripted_stack([pick([ICO], QUOTE)], tmp_path)
    report = run_gold([ICO_CASE, ABSENT], [ico_finding()], stack)
    assert [row.result for row in report.rows] == ["correct", "missing"]
    assert report.rows[0].selected == (ICO,)
    assert (report.scored, report.accuracy, report.go) == (1, 1.0, True)
    assert len(live.requests) == 1


def test_invented_names_are_a_no_go_even_when_accurate(tmp_path: Path) -> None:
    rows = tuple(GoldRow(ICO_CASE, "correct") for _ in range(9))
    hallucinated = GoldRow(ICO_CASE, "rejected", detail="selected names that are not candidates: x")
    report = GoldReport((*rows, hallucinated))
    assert report.accuracy == 0.9
    assert report.hallucinations == 1
    assert not report.go


def test_run_gold_records_wrong_rejected_and_errors(tmp_path: Path) -> None:
    findings = [ico_finding()]
    cases: list[tuple[Reply, str]] = [
        (pick([ICNS], QUOTE), "wrong"),
        (pick([ICO], "not in the advisory text at all"), "rejected"),
        (ModelError("boom"), "error"),
    ]
    for reply, expected in cases:
        stack, _ = scripted_stack([reply], tmp_path)
        assert run_gold([ICO_CASE], findings, stack).rows[0].result == expected
    l2 = ico_finding(level=Level.L2_MODULE)
    stack, _ = scripted_stack([], tmp_path)
    assert run_gold([ICO_CASE], [l2], stack).rows[0].result == "missing"
    assert not GoldReport(()).go


def test_run_gold_stops_when_the_budget_runs_out(tmp_path: Path) -> None:
    stack, _ = scripted_stack([pick([ICO], QUOTE)], tmp_path, max_tokens=1)
    run_gold([ICO_CASE], [ico_finding()], stack)
    with pytest.raises(BudgetExceededError):
        run_gold([ICO_CASE], [ico_finding(details="other text so the request differs")], stack)
