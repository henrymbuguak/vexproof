"""What a model call costs, per model, priced one request at a time (ADR 0018).

Claude's list prices, checked against the pricing page on the date below. Four token kinds have
four rates: input billed in full, cache writes (5-minute), cache reads, and output. Claude Haiku
5.5 also prices by prompt length, per request: a request whose prompt (input plus cache reads and
writes) is over 100,000 tokens pays its higher rates. So cost is worked out per call, never from
totals.

Models without an entry here (Muse Spark, Ollama models) have no price unless
`VEXPROOF_PRICE_INPUT_PER_M` and `VEXPROOF_PRICE_OUTPUT_PER_M` are set; those set prices for every
model, flat, with cache tokens at the input rate.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

PRICES_CHECKED = "2026-11-19"
PRICES_SOURCE = "https://platform.claude.com/docs/en/about-claude/pricing"


@dataclass(frozen=True)
class Rates:
    """USD per million tokens."""

    input: float
    cache_write: float
    cache_read: float
    output: float


@dataclass(frozen=True)
class Price:
    rates: Rates
    long_prompt: Rates | None = None  # rates for a request whose prompt is over the threshold
    long_prompt_over: int = 100_000

    def cost(
        self,
        *,
        input_tokens: int,
        cache_write_tokens: int,
        cache_read_tokens: int,
        output_tokens: int,
    ) -> float:
        """USD for one request."""
        prompt = input_tokens + cache_write_tokens + cache_read_tokens
        rates = (
            self.long_prompt
            if self.long_prompt is not None and prompt > self.long_prompt_over
            else self.rates
        )
        return (
            input_tokens * rates.input
            + cache_write_tokens * rates.cache_write
            + cache_read_tokens * rates.cache_read
            + output_tokens * rates.output
        ) / 1e6


PRICES: dict[str, Price] = {
    "claude-opus-5-5": Price(Rates(input=4.0, cache_write=5.0, cache_read=0.20, output=20.0)),
    "claude-sonnet-5-5": Price(Rates(input=2.0, cache_write=2.5, cache_read=0.10, output=10.0)),
    "claude-haiku-5-5": Price(
        Rates(input=0.10, cache_write=0.125, cache_read=0.01, output=0.50),
        long_prompt=Rates(input=0.50, cache_write=0.625, cache_read=0.05, output=2.50),
    ),
}

PriceOf = Callable[[str], Price | None]


def price_lookup(
    input_per_m: float | None = None, output_per_m: float | None = None
) -> tuple[PriceOf, str]:
    """How to price a model, and where those prices come from (for reports)."""
    if input_per_m is not None and output_per_m is not None:
        flat = Price(Rates(input_per_m, input_per_m, input_per_m, output_per_m))
        return (lambda _model: flat), "VEXPROOF_PRICE_INPUT_PER_M / VEXPROOF_PRICE_OUTPUT_PER_M"
    return PRICES.get, f"list prices checked {PRICES_CHECKED}"
