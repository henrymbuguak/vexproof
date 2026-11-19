"""Assemble the model stack from explicit settings (no global configuration here)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import openai

from vexproof.llm.budget import BudgetTransport
from vexproof.llm.claude import ClaudeTransport, list_claude_models
from vexproof.llm.meta import MetaTransport
from vexproof.llm.pricing import price_lookup
from vexproof.llm.recording import Mode, RecordingTransport
from vexproof.llm.structured import StructuredCaller
from vexproof.llm.types import Effort, ModelError, Transport, is_local_endpoint

# "responses" and "chat": OpenAI-compatible endpoints (Muse Spark, Ollama) through MetaTransport;
# "anthropic": Claude's Messages API through ClaudeTransport.
Api = Literal["responses", "chat", "anthropic"]


@dataclass(frozen=True)
class ModelConfig:
    api_key: str | None
    base_url: str
    model: str
    api: Api = "responses"
    mode: Mode = "cache"
    max_tokens: int = 1_000_000
    recordings_dir: Path = Path(".vexproof-cache/model")
    timeout_s: float = 120.0
    workers: int = 4
    effort: Effort | None = None  # sent on every request when set (Claude's output_config.effort)
    fallbacks: bool = True  # Claude: retry a refused request on the server's fallback model
    # flat USD per million tokens, for every model; both unset: the list prices in pricing.py
    price_input_per_m: float | None = None
    price_output_per_m: float | None = None

    @property
    def local(self) -> bool:
        return self.api != "anthropic" and is_local_endpoint(self.base_url)

    @property
    def ready(self) -> bool:
        """Enough configuration to call (or replay) a model. Claude's SDK finds its own
        credentials, so choosing the anthropic API is enough; a missing one fails at the call."""
        return self.api == "anthropic" or bool(self.api_key) or self.local or self.mode == "replay"


@dataclass
class ModelStack:
    caller: StructuredCaller
    budget: BudgetTransport
    workers: int = 4
    prices: str = ""  # where the prices in usage reports come from

    @property
    def label(self) -> str:
        return self.caller.model


def build_stack(config: ModelConfig, live: Transport | None = None) -> ModelStack:
    """Budget -> recording -> live transport. `live` lets tests inject a scripted transport."""
    if live is None and config.mode != "replay":
        if not config.ready:
            raise ModelError("MODEL_API_KEY is not set; add it to .env or use --no-model")
        if config.api == "anthropic":
            live = ClaudeTransport(
                model=config.model, timeout_s=config.timeout_s, fallbacks=config.fallbacks
            )
        else:
            live = MetaTransport(
                api_key=config.api_key or "local",  # local servers ignore it; the SDK needs one
                base_url=config.base_url,
                model=config.model,
                api=config.api,
                timeout_s=config.timeout_s,
            )
    recorder = RecordingTransport(live, config.recordings_dir, config.mode, model=config.model)
    price_of, prices = price_lookup(config.price_input_per_m, config.price_output_per_m)
    budget = BudgetTransport(recorder, config.max_tokens, price_of)
    caller = StructuredCaller(budget, effort=config.effort)
    return ModelStack(caller=caller, budget=budget, workers=config.workers, prices=prices)


def list_models(
    api_key: str, base_url: str, client: openai.OpenAI | None = None, *, api: Api = "responses"
) -> list[str]:
    """Model ids the credentials can use, if the endpoint supports listing."""
    if api == "anthropic":
        return list_claude_models()
    try:
        client = client or openai.OpenAI(
            api_key=api_key, base_url=base_url, max_retries=1, timeout=30
        )
        return sorted(m.id for m in client.models.list())
    except openai.OpenAIError as exc:
        raise ModelError(f"could not list models: {exc}") from exc
