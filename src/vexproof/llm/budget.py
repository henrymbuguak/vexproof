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
    """Tokens spent by this run; `recorded_*` are what replayed answers cost when first made."""

    calls: int = 0
    replayed: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    recorded_input_tokens: int = 0
    recorded_output_tokens: int = 0


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
            total.recorded_input_tokens += usage.recorded_input_tokens
            total.recorded_output_tokens += usage.recorded_output_tokens
        return total

    def cost_usd(
        self, input_per_m: float | None, output_per_m: float | None, *, fresh: bool = False
    ) -> float | None:
        """What this run cost; with `fresh`, what it would cost with no recordings."""
        if input_per_m is None or output_per_m is None:
            return None
        t = self.total
        tokens_in = t.input_tokens + (t.recorded_input_tokens if fresh else 0)
        tokens_out = t.output_tokens + (t.recorded_output_tokens if fresh else 0)
        return (tokens_in * input_per_m + tokens_out * output_per_m) / 1e6


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
            if response.replayed:  # recorded answers cost nothing now; keep what they cost then
                usage.replayed += 1
                usage.recorded_input_tokens += response.input_tokens
                usage.recorded_output_tokens += response.output_tokens
            else:
                usage.input_tokens += response.input_tokens
                usage.output_tokens += response.output_tokens
        return response
