from __future__ import annotations

from pathlib import Path

import pytest

from tests.codebase import FRAME, build
from tests.llm_fakes import Reply, scripted_stack
from vexproof.evidence.paths import registry_edges
from vexproof.evidence.trace import MAX_STEPS, PROMPT_VERSION, Tracer
from vexproof.llm.types import BudgetExceededError, ModelError, ModelRequest
from vexproof.static.codeindex import CodeIndex

# A library edit that removes the registry, so reaching `frame` needs an uncertain hop.
NO_REGISTRY = "PIL/IcoPlugin.py"


def _act(action: str, **fields: object) -> dict[str, object]:
    return {"action": action, "avoid": [], "through": [], "symbol": "", "reason": "r", **fields}


@pytest.fixture
def index(tmp_path: Path) -> CodeIndex:
    return build(tmp_path)[1]


@pytest.fixture
def loose_index(tmp_path: Path) -> CodeIndex:
    from tests.codebase import LIBRARY

    library = {
        **LIBRARY,
        NO_REGISTRY: LIBRARY[NO_REGISTRY].replace('Image.register_open("ICO", IcoImageFile)\n', ""),
    }
    return build(tmp_path, library=library)[1]


def test_certain_path_needs_no_model(index: CodeIndex, tmp_path: Path) -> None:
    stack, live = scripted_stack([], tmp_path)
    outcome = Tracer(index, registry_edges(index), stack.caller).trace(FRAME)
    assert outcome.path is not None
    assert outcome.path.hops[0].symbol == "shop.views.thumbnail"
    assert not outcome.reviewed
    assert outcome.note == "every hop of the path is certain"
    assert live.requests == []


def test_no_path_needs_no_model(index: CodeIndex, tmp_path: Path) -> None:
    stack, live = scripted_stack([], tmp_path)
    tracer = Tracer(index, registry_edges(index), stack.caller)
    outcome = tracer.trace("PIL.ImageMath.eval")
    assert outcome.path is None
    assert "not found in the loaded code" in outcome.note
    no_route = tracer.trace("PIL.IcoPlugin._save")  # nothing in the project calls Image.save
    assert no_route.path is None
    assert "no call path from your code" in no_route.note
    assert live.requests == []


def test_without_a_model_the_candidate_is_kept_aside(loose_index: CodeIndex) -> None:
    outcome = Tracer(loose_index, registry_edges(loose_index), None).trace(FRAME)
    assert outcome.path is None
    assert outcome.candidate is not None
    assert "1 uncertain hop(s) exists; a model must review it" in outcome.note


def test_model_accepts_after_looking(loose_index: CodeIndex, tmp_path: Path) -> None:
    stack, live = scripted_stack(
        [
            _act("callers", symbol=FRAME),
            _act("source", symbol="shop.views.process"),
            _act("source", symbol="no.such"),
            _act("accept", reason="process receives IcoFile objects"),
        ],
        tmp_path,
    )
    outcome = Tracer(loose_index, registry_edges(loose_index), stack.caller).trace(FRAME)
    assert outcome.path is not None
    assert outcome.reviewed
    assert outcome.note == "process receives IcoFile objects"
    first, last = live.requests[0], live.requests[-1]
    assert (first.purpose, first.prompt_version) == ("trace_path", PROMPT_VERSION)
    assert "POSSIBLE shop.views.process" not in first.user  # the start is marked "start"
    assert "POSSIBLE PIL.IcoPlugin.IcoFile.frame" in first.user
    assert "certain  PIL.IcoPlugin.IcoFile.getimage line 12" in last.user  # callers listing
    assert "def process(obj):" in last.user
    assert "unknown function" in last.user


def test_model_searches_around_a_wrong_hop(loose_index: CodeIndex, tmp_path: Path) -> None:
    stack, live = scripted_stack(
        [
            _act("search", avoid=["shop.views.process"]),
            _act("give_up", reason="nothing in the project handles ICO files"),
        ],
        tmp_path,
    )
    outcome = Tracer(loose_index, registry_edges(loose_index), stack.caller).trace(FRAME)
    assert outcome.path is None
    assert outcome.reviewed
    assert outcome.note.startswith("model found no plausible path: nothing in the project")
    assert "There is no current candidate path." in live.requests[1].user
    assert "no verified path with those constraints" in live.requests[1].user


def test_review_limits_and_errors(loose_index: CodeIndex, tmp_path: Path) -> None:
    extra = registry_edges(loose_index)
    stuck, live = scripted_stack(lambda _: _act("callers", symbol=FRAME), tmp_path / "a")
    outcome = Tracer(loose_index, extra, stuck.caller).trace(FRAME)
    assert outcome.path is None
    assert f"within {MAX_STEPS} steps" in outcome.note
    assert len(live.requests) == MAX_STEPS

    broken, _ = scripted_stack([ModelError("server down")], tmp_path / "b")
    failed = Tracer(loose_index, extra, broken.caller).trace(FRAME)
    assert failed.path is None
    assert failed.note == "path review failed: server down"

    poor, _ = scripted_stack(lambda _: _act("callers", symbol=FRAME), tmp_path / "c", max_tokens=1)
    with pytest.raises(BudgetExceededError):
        Tracer(loose_index, extra, poor.caller).trace(FRAME)


def test_accepting_nothing_is_not_accepting(loose_index: CodeIndex, tmp_path: Path) -> None:
    def script(request: ModelRequest) -> Reply:
        if "There is no current candidate path." in request.user:
            return _act("accept")
        return _act("search", avoid=["shop.views.process"])

    stack, live = scripted_stack(script, tmp_path)
    outcome = Tracer(loose_index, registry_edges(loose_index), stack.caller).trace(FRAME)
    assert outcome.path is None
    assert "there is no current path to accept" in live.requests[2].user


def test_one_answer_per_function(loose_index: CodeIndex, tmp_path: Path) -> None:
    stack, live = scripted_stack(lambda _: _act("accept"), tmp_path)
    tracer = Tracer(loose_index, registry_edges(loose_index), stack.caller)
    assert tracer.trace(FRAME) is tracer.trace(FRAME)
    assert len(live.requests) == 1


def test_applying_reviewed_and_missing_paths(loose_index: CodeIndex, tmp_path: Path) -> None:
    from vexproof.domain import Advisory, Evidence, Finding, Level, Package, Verdict
    from vexproof.evidence.apply import PATH_REVIEWED, apply_trace

    finding = Finding(
        id="x",
        package=Package(name="pillow", version="9.0.0"),
        advisory=Advisory(id="GHSA-x"),
        evidence=Evidence(level=Level.L1_SYMBOL, vulnerable_symbols=(FRAME,)),
    )
    stack, _ = scripted_stack([_act("accept", reason="it holds")], tmp_path)
    reviewed = Tracer(loose_index, registry_edges(loose_index), stack.caller).trace(FRAME)
    applied = apply_trace(finding, FRAME, reviewed, "fake-model / trace_path.v1")
    assert applied.verdict is Verdict.AFFECTED
    assert applied.evidence is not None
    assert applied.evidence.chain_model == "fake-model / trace_path.v1"
    assert PATH_REVIEWED in applied.evidence.checks_passed
    assert (
        "1 uncertain hop(s) judged plausible by the model: it holds" in applied.evidence.notes[-1]
    )

    unreviewed = Tracer(loose_index, registry_edges(loose_index), None).trace(FRAME)
    kept = apply_trace(finding, FRAME, unreviewed, None)
    assert kept.verdict is None
    assert kept.evidence is not None
    assert (
        "(candidate: shop.views.process -> PIL.IcoPlugin.IcoFile.frame)" in kept.evidence.notes[-1]
    )
    bare = finding.model_copy(update={"evidence": None})
    assert apply_trace(bare, FRAME, unreviewed, None) is bare


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        ({"action": "accept"}, ("accept", [], [], "", "")),  # empty fields left out
        (
            {"name": "search", "arguments": {"avoid": "x.y", "through": None}},
            ("search", ["x.y"], [], "", ""),
        ),  # tool-call shape, a string for a list
        ({"TraceAction": {"tool": "Give Up", "explanation": "no"}}, ("give_up", [], [], "", "no")),
        ({"action": "callers", "target": "a.b", "extra": 1}, ("callers", [], [], "a.b", "")),
    ],
)
def test_review_replies_in_other_shapes(
    reply: dict[str, object], expected: tuple[object, ...]
) -> None:
    from vexproof.evidence.trace import TraceAction

    act = TraceAction.model_validate(reply)
    assert (act.action, act.avoid, act.through, act.symbol, act.reason) == expected


def test_unknown_actions_still_fail_and_say_what_came_back(tmp_path: Path) -> None:
    from vexproof.evidence.trace import TraceAction
    from vexproof.llm.types import ModelOutputInvalidError

    stack, _ = scripted_stack(
        [{"action": "dance"}, {"action": "dance", "reason": "again"}], tmp_path
    )
    with pytest.raises(ModelOutputInvalidError, match=r"the reply began '\{\"action\": \"dance\""):
        stack.caller.ask(TraceAction, purpose="t", prompt_version="t.v1", system="s", user="u")
