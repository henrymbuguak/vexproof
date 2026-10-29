"""Requests, responses and errors shared by all transports."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from vexproof.errors import VexproofError


class ModelError(VexproofError):
    """The model service failed or rejected the request."""


class ModelOutputInvalidError(ModelError):
    """The model's reply did not match the requested schema, even after one repair attempt."""


class ModelReplayMissError(ModelError):
    """Replay mode was requested but no recording matches this request."""


class BudgetExceededError(ModelError):
    """The token budget for this run is used up."""


@dataclass(frozen=True)
class ModelRequest:
    purpose: str  # e.g. "symbol_pick"; used for cost reporting and recordings
    prompt_version: str  # e.g. "symbol_pick.v1"
    system: str
    user: str
    schema_name: str
    schema: dict[str, Any] = field(hash=False)
    max_output_tokens: int = 2000

    def key(self, model: str) -> str:
        """Stable identity of a request: same inputs and model -> same recorded answer."""
        material = json.dumps(
            [model, self.prompt_version, self.system, self.user, self.schema_name, self.schema],
            sort_keys=True,
        )
        return hashlib.sha256(material.encode()).hexdigest()


@dataclass(frozen=True)
class ModelResponse:
    text: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    replayed: bool = False


class Transport(Protocol):
    @property
    def model(self) -> str: ...

    def complete(self, request: ModelRequest) -> ModelResponse: ...
