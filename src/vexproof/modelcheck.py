"""`vexproof check-model`: is the Model API usable, and is the model good enough to trust?

Three independent checks, each cheap:
1. which models the key can see;
2. a tiny structured-output request on the configured API, falling back to the other one;
3. the gold symbol-selection set: the model answers each gold advisory, the verifier checks
   every answer, and the results are scored against labels written before any model was run.

The verdict is GO only if the model is accurate enough *and* never named a function that was
not a candidate: a model that invents names cannot be the first stage of an evidence chain.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict

from vexproof.domain import Finding
from vexproof.llm.factory import ModelStack
from vexproof.llm.meta import Api
from vexproof.llm.types import BudgetExceededError, ModelError
from vexproof.symbols.gold import GoldCase, Judgement, judge
from vexproof.symbols.select import pick_symbols
from vexproof.symbols.verify import Rejected, Verified, verify

MIN_ACCURACY = 0.75
PING_PROMPT = "ping.v1"
PING_MAX_OUTPUT_TOKENS = 1024  # room for a reasoning model to think before a one-line answer

CaseResult = Judgement | Literal["missing", "error"]


class Ping(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    word: str


@dataclass(frozen=True)
class PingResult:
    api: Api | None
    errors: dict[str, str]


def ping(stack_for: Callable[[Api], ModelStack], prefer: Api = "responses") -> PingResult:
    """Try structured output on the configured API, then the other; return the first that works."""
    errors: dict[str, str] = {}
    apis: tuple[Api, ...] = (
        ("responses", "chat") if prefer == "responses" else ("chat", "responses")
    )
    for api in apis:
        try:
            reply = stack_for(api).caller.ask(
                Ping,
                purpose="ping",
                prompt_version=PING_PROMPT,
                system="You are a connectivity check. Reply with JSON only.",
                user='Set ok to true and word to "vexproof".',
                max_output_tokens=PING_MAX_OUTPUT_TOKENS,
            )
        except ModelError as exc:
            errors[api] = str(exc)
            continue
        if reply.ok and reply.word.strip().lower() == "vexproof":
            return PingResult(api=api, errors=errors)
        errors[api] = f"unexpected reply: {reply.model_dump()}"
    return PingResult(api=None, errors=errors)


@dataclass(frozen=True)
class GoldRow:
    case: GoldCase
    result: CaseResult
    selected: tuple[str, ...] = ()
    detail: str = ""

    @property
    def hallucinated(self) -> bool:
        return self.result == "rejected" and "not candidates" in self.detail


@dataclass(frozen=True)
class GoldReport:
    rows: tuple[GoldRow, ...]

    def count(self, result: CaseResult) -> int:
        return sum(1 for row in self.rows if row.result == result)

    @property
    def scored(self) -> int:
        return sum(1 for row in self.rows if row.result in {"correct", "wrong", "rejected"})

    @property
    def accuracy(self) -> float:
        return self.count("correct") / self.scored if self.scored else 0.0

    @property
    def hallucinations(self) -> int:
        return sum(1 for row in self.rows if row.hallucinated)

    @property
    def go(self) -> bool:
        return self.scored > 0 and self.accuracy >= MIN_ACCURACY and self.hallucinations == 0


def run_gold(
    cases: Iterable[GoldCase], findings: Sequence[Finding], stack: ModelStack
) -> GoldReport:
    by_id = {f.advisory.id: f for f in findings}
    rows: list[GoldRow] = []
    for case in cases:
        finding = by_id.get(case.advisory)
        if finding is None or finding.evidence is None or not finding.evidence.candidates:
            rows.append(GoldRow(case, "missing", detail="not in findings or no candidates"))
            continue
        try:
            outcome: Verified | Rejected = verify(pick_symbols(finding, stack.caller), finding)
        except BudgetExceededError:
            raise
        except ModelError as exc:
            rows.append(GoldRow(case, "error", detail=str(exc)))
            continue
        if isinstance(outcome, Rejected):
            rows.append(GoldRow(case, "rejected", detail="; ".join(outcome.reasons)))
            continue
        shown = ("none_match",) if outcome.none_match else outcome.selected
        rows.append(GoldRow(case, judge(case, outcome), selected=shown, detail=outcome.confidence))
    return GoldReport(tuple(rows))
