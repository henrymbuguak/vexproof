"""A scripted model transport: tests decide every reply, and every request is kept for asserts."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from pathlib import Path

from vexproof.llm.factory import ModelConfig, ModelStack, build_stack
from vexproof.llm.recording import Mode
from vexproof.llm.types import ModelError, ModelRequest, ModelResponse

Reply = str | dict[str, object] | ModelError
Script = Callable[[ModelRequest], Reply]


class ScriptedTransport:
    def __init__(self, script: Script | list[Reply], model: str = "fake-model") -> None:
        self._script = script
        self._model = model
        self._lock = threading.Lock()
        self.requests: list[ModelRequest] = []

    @property
    def model(self) -> str:
        return self._model

    def complete(self, request: ModelRequest) -> ModelResponse:
        with self._lock:
            self.requests.append(request)
            reply = self._script(request) if callable(self._script) else self._script.pop(0)
        if isinstance(reply, ModelError):
            raise reply
        text = reply if isinstance(reply, str) else json.dumps(reply)
        return ModelResponse(text=text, model=self._model, input_tokens=100, output_tokens=20)


def scripted_stack(
    script: Script | list[Reply],
    tmp: Path,
    *,
    mode: Mode = "live",
    max_tokens: int = 1_000_000,
) -> tuple[ModelStack, ScriptedTransport]:
    live = ScriptedTransport(script)
    config = ModelConfig(
        api_key=None,
        base_url="https://api.test/v1",
        model="fake-model",
        mode=mode,
        max_tokens=max_tokens,
        recordings_dir=tmp / "model",
    )
    return build_stack(config, live=live), live


def pick(
    selected: list[str],
    quote: str,
    *,
    none_match: bool = False,
    confidence: str = "high",
) -> dict[str, object]:
    return {
        "selected": selected,
        "none_match": none_match,
        "advisory_quote": quote,
        "rationale": "the advisory describes this function",
        "confidence": confidence,
    }
