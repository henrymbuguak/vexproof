"""Assemble the model stack from explicit settings (no global configuration here)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import openai

from vexproof.llm.budget import BudgetTransport
from vexproof.llm.meta import Api, MetaTransport
from vexproof.llm.recording import Mode, RecordingTransport
from vexproof.llm.structured import StructuredCaller
from vexproof.llm.types import ModelError, Transport, is_local_endpoint


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

    @property
    def local(self) -> bool:
        return is_local_endpoint(self.base_url)

    @property
    def ready(self) -> bool:
        """Enough configuration to call (or replay) a model."""
        return bool(self.api_key) or self.local or self.mode == "replay"


@dataclass
class ModelStack:
    caller: StructuredCaller
    budget: BudgetTransport
    workers: int = 4

    @property
    def label(self) -> str:
        return self.caller.model


def build_stack(config: ModelConfig, live: Transport | None = None) -> ModelStack:
    """Budget -> recording -> live transport. `live` lets tests inject a scripted transport."""
    if live is None and config.mode != "replay":
        if not config.ready:
            raise ModelError("MODEL_API_KEY is not set; add it to .env or use --no-model")
        live = MetaTransport(
            api_key=config.api_key or "local",  # local servers ignore the key; the SDK needs one
            base_url=config.base_url,
            model=config.model,
            api=config.api,
            timeout_s=config.timeout_s,
        )
    recorder = RecordingTransport(live, config.recordings_dir, config.mode, model=config.model)
    budget = BudgetTransport(recorder, config.max_tokens)
    return ModelStack(caller=StructuredCaller(budget), budget=budget, workers=config.workers)


def list_models(api_key: str, base_url: str, client: openai.OpenAI | None = None) -> list[str]:
    """Model ids the key can use, if the endpoint supports listing."""
    try:
        client = client or openai.OpenAI(
            api_key=api_key, base_url=base_url, max_retries=1, timeout=30
        )
        return sorted(m.id for m in client.models.list())
    except openai.OpenAIError as exc:
        raise ModelError(f"could not list models: {exc}") from exc
