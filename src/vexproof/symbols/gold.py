"""Gold labels for symbol selection, and how a model's pick is judged against them."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vexproof.errors import IngestError
from vexproof.symbols.verify import Rejected, Verified

Judgement = Literal["correct", "wrong", "rejected"]


class GoldCase(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    advisory: str
    package: str
    expected: tuple[str, ...] | Literal["none"]
    must_include: tuple[str, ...] = ()
    why: str = Field(min_length=1)


def load_gold(path: Path) -> tuple[GoldCase, ...]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return tuple(GoldCase.model_validate(case) for case in data["cases"])
    except (OSError, yaml.YAMLError, KeyError, TypeError, ValidationError) as exc:
        raise IngestError(f"cannot read gold file {path}: {exc}") from exc


def judge(case: GoldCase, outcome: Verified | Rejected) -> Judgement:
    if isinstance(outcome, Rejected):
        return "rejected"
    if case.expected == "none":
        return "correct" if outcome.none_match else "wrong"
    chosen = set(outcome.selected)
    ok = (
        not outcome.none_match
        and bool(chosen)
        and chosen <= set(case.expected)
        and set(case.must_include) <= chosen
    )
    return "correct" if ok else "wrong"
