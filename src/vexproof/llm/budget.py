"""Count tokens per purpose and stop before a run exceeds its budget.

Prices are optional: set VEXPROOF_PRICE_INPUT_PER_M / VEXPROOF_PRICE_OUTPUT_PER_M (USD per million
tokens) from the Model API pricing page to see costs; budgets are in tokens either way.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from vexproof.llm.types import BudgetExceededError, ModelRequest, ModelResponse, Transport


@dataclass
class Usage:
    calls: int = 0
    replayed: int = 0
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class UsageReport:
    by_purpose: dict[str, Usage] = field(default_factory=dict)

    @property
    def total(self) -> Usage:
        total = Usage()
        for usage in self.by_purpose.values():
            total.calls += usage.calls
            total.replayed += usage.replayed
            total.input_tokens += usage.input_tokens
            total.output_tokens += usage.output_tokens
        return total

    def cost_usd(self, input_per_m: float | None, output_per_m: float | None) -> float | None:
        if input_per_m is None or output_per_m is None:
            return None
        total = self.total
        return (total.input_tokens * input_per_m + total.output_tokens * output_per_m) / 1e6


class BudgetTransport:
    def __init__(self, inner: Transport, max_tokens: int) -> None:
        self._inner = inner
        self._max = max_tokens
        self._lock = threading.Lock()
        self.report = UsageReport()

    @property
    def model(self) -> str:
        return self._inner.model

    def _spent(self) -> int:
        total = self.report.total
        return total.input_tokens + total.output_tokens

    def complete(self, request: ModelRequest) -> ModelResponse:
        with self._lock:
            if self._spent() >= self._max:
                raise BudgetExceededError(
                    f"token budget of {self._max:,} reached (VEXPROOF_MODEL_MAX_TOKENS)"
                )
        response = self._inner.complete(request)
        with self._lock:
            usage = self.report.by_purpose.setdefault(request.purpose, Usage())
            usage.calls += 1
            if response.replayed:
                usage.replayed += 1  # recorded answers cost nothing
            else:
                usage.input_tokens += response.input_tokens
                usage.output_tokens += response.output_tokens
        return response
