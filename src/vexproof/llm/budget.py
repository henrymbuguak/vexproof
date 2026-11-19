"""Count tokens and cost per purpose, and stop before a run exceeds its token budget.

Every call is priced on its own (see `pricing.py`), at the rates of the model that served it: a
refusal fallback can answer from another model. A replayed answer costs nothing now; what it cost
when it was recorded is kept separately, so a report can say what a run without recordings costs.

The budget counts every token a live call processes: input, output, cache writes and cache reads.
Cache reads are cheap, so this is conservative in dollars; it keeps the budget a hard ceiling on
the work done, whatever the prices.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field, fields

from vexproof.llm.pricing import PriceOf
from vexproof.llm.types import BudgetExceededError, ModelRequest, ModelResponse, Transport


@dataclass
class Usage:
    """Tokens and cost of this run; `recorded_*` are what replayed answers cost when first made."""

    calls: int = 0
    replayed: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    cost_usd: float = 0.0
    recorded_input_tokens: int = 0
    recorded_output_tokens: int = 0
    recorded_cache_read_tokens: int = 0
    recorded_cache_write_tokens: int = 0
    recorded_cost_usd: float = 0.0

    def add(self, other: Usage) -> None:
        for f in fields(self):
            setattr(self, f.name, getattr(self, f.name) + getattr(other, f.name))

    @property
    def tokens(self) -> int:
        """Every token live calls processed: what the budget counts."""
        return (
            self.input_tokens
            + self.output_tokens
            + self.cache_read_tokens
            + self.cache_write_tokens
        )


@dataclass
class UsageReport:
    by_purpose: dict[str, Usage] = field(default_factory=dict)
    priced: bool = False  # False when some call's model had no price: costs are then unknown

    @property
    def total(self) -> Usage:
        total = Usage()
        for usage in self.by_purpose.values():
            total.add(usage)
        return total

    def cost_usd(self, *, fresh: bool = False) -> float | None:
        """What this run cost; with `fresh`, what it would cost with no recordings."""
        if not self.priced:
            return None
        total = self.total
        return total.cost_usd + (total.recorded_cost_usd if fresh else 0.0)


class BudgetTransport:
    def __init__(self, inner: Transport, max_tokens: int, prices: PriceOf | None = None) -> None:
        self._inner = inner
        self._max = max_tokens
        self._prices = prices
        self._lock = threading.Lock()
        self.report = UsageReport(priced=prices is not None)

    @property
    def model(self) -> str:
        return self._inner.model

    def complete(self, request: ModelRequest) -> ModelResponse:
        with self._lock:
            if self.report.total.tokens >= self._max:
                raise BudgetExceededError(
                    f"token budget of {self._max:,} reached (VEXPROOF_MODEL_MAX_TOKENS)"
                )
        response = self._inner.complete(request)
        cost = self._cost(response)
        with self._lock:
            usage = self.report.by_purpose.setdefault(request.purpose, Usage())
            usage.calls += 1
            if response.replayed:  # recorded answers cost nothing now; keep what they cost then
                usage.replayed += 1
                usage.recorded_input_tokens += response.input_tokens
                usage.recorded_output_tokens += response.output_tokens
                usage.recorded_cache_read_tokens += response.cache_read_tokens
                usage.recorded_cache_write_tokens += response.cache_write_tokens
                usage.recorded_cost_usd += cost or 0.0
            else:
                usage.input_tokens += response.input_tokens
                usage.output_tokens += response.output_tokens
                usage.cache_read_tokens += response.cache_read_tokens
                usage.cache_write_tokens += response.cache_write_tokens
                usage.cost_usd += cost or 0.0
            if cost is None:
                self.report.priced = False
        return response

    def _cost(self, response: ModelResponse) -> float | None:
        if self._prices is None:
            return None
        # the model that served it (a fallback model after a refusal), else the configured one
        price = (self._prices(response.model) if response.model else None) or self._prices(
            self._inner.model
        )
        if price is None:
            return None
        return price.cost(
            input_tokens=response.input_tokens,
            cache_write_tokens=response.cache_write_tokens,
            cache_read_tokens=response.cache_read_tokens,
            output_tokens=response.output_tokens,
        )
