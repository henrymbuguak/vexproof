"""Record model responses and replay them, so runs are reproducible and re-runs are free.

Modes:
- `cache` (default): replay a matching recording if there is one, otherwise call and record;
- `replay`: only replay; a request with no recording is an error (tests, the eval);
- `live`: always call, never record.

Recordings are JSON lines, one file per purpose, keyed by a hash of the model, prompt version,
prompts and schema. Changing any of them is a new request, so a stale answer is never reused.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Literal

from vexproof.llm.types import ModelReplayMissError, ModelRequest, ModelResponse, Transport

Mode = Literal["cache", "replay", "live"]


class RecordingTransport:
    def __init__(
        self,
        inner: Transport | None,
        directory: Path,
        mode: Mode = "cache",
        *,
        model: str | None = None,
    ) -> None:
        """`model` names the recordings to replay when there is no live transport."""
        if inner is None and mode != "replay":
            raise ValueError("a live transport is required unless mode is 'replay'")
        if inner is None and not model:
            raise ValueError("replay without a live transport needs the model name")
        self._inner = inner
        self._dir = directory
        self._mode = mode
        self._model = inner.model if inner else str(model)
        self._lock = threading.Lock()
        self._loaded: dict[str, dict[str, ModelResponse]] = {}

    @property
    def model(self) -> str:
        return self._model

    def _file(self, purpose: str) -> Path:
        return self._dir / f"{purpose}.jsonl"

    def _recordings(self, purpose: str) -> dict[str, ModelResponse]:
        if purpose not in self._loaded:
            found: dict[str, ModelResponse] = {}
            path = self._file(purpose)
            if path.is_file():
                for line in path.read_text(encoding="utf-8").splitlines():
                    row = json.loads(line)
                    found[row["key"]] = ModelResponse(**row["response"], replayed=True)
            self._loaded[purpose] = found
        return self._loaded[purpose]

    def complete(self, request: ModelRequest) -> ModelResponse:
        with self._lock:
            recordings = self._recordings(request.purpose)
            hit = recordings.get(request.key(self._model)) if self._mode != "live" else None
            if hit is not None:
                return hit
            if self._mode == "replay":
                raise ModelReplayMissError(
                    f"no recording for this {request.purpose} request "
                    f"({request.prompt_version}, {self._model})"
                )
        assert self._inner is not None  # noqa: S101 - guaranteed by __init__
        response = self._inner.complete(request)
        if self._mode == "cache":
            self._store(request, response)
        return response

    def _store(self, request: ModelRequest, response: ModelResponse) -> None:
        key = request.key(self._model)
        recorded = ModelResponse(
            text=response.text,
            model=self._model,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            replayed=True,
        )
        row = {
            "key": key,
            "prompt_version": request.prompt_version,
            "response": {
                "text": recorded.text,
                "model": recorded.model,
                "input_tokens": recorded.input_tokens,
                "output_tokens": recorded.output_tokens,
            },
        }
        with self._lock:
            self._dir.mkdir(parents=True, exist_ok=True)
            with self._file(request.purpose).open("a", encoding="utf-8") as out:
                out.write(json.dumps(row, sort_keys=True) + "\n")
            self._recordings(request.purpose)[key] = recorded
