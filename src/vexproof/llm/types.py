"""Requests, responses and errors shared by all transports (ADR 0013).

A request is a system prompt and a list of messages, optionally with tools and a response schema.
Transports are vendor adapters that translate it; nothing outside `llm/` sees a vendor SDK.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit

from vexproof.errors import VexproofError


class ModelError(VexproofError):
    """The model service failed or rejected the request."""


class ModelOutputInvalidError(ModelError):
    """The model's reply did not match the requested schema, even after one repair attempt."""


class ModelReplayMissError(ModelError):
    """Replay mode was requested but no recording matches this request."""


class BudgetExceededError(ModelError):
    """The token budget for this run is used up."""


class ModelRefusedError(ModelError):
    """The model declined the request (`stop_reason: refusal`). Never read as a negative answer."""


class ModelTruncatedError(ModelError):
    """The reply hit the output limit (`stop_reason: max_tokens`) before the answer was complete."""


Role = Literal["user", "assistant"]
# How hard the model thinks before answering (Claude's `output_config.effort`). It changes the
# answer, so it is part of a request's identity; None means the transport's default.
Effort = Literal["low", "medium", "high", "xhigh", "max"]
# Why a reply ended, in one vocabulary for every transport; "" when the transport did not say
# (and for answers recorded before stop reasons were kept).
StopReason = Literal["", "end_turn", "max_tokens", "tool_use", "refusal"]


@dataclass(frozen=True)
class Message:
    role: Role
    content: str


@dataclass(frozen=True)
class ToolSpec:
    """A tool the model may call: its name, when to use it, and the JSON schema of its input."""

    name: str
    description: str
    input_schema: dict[str, Any] = field(hash=False)


@dataclass(frozen=True)
class ToolCall:
    """One tool call in a reply: the id ties it to its result in the next request."""

    id: str
    name: str
    input: dict[str, Any] = field(hash=False)


@dataclass(frozen=True)
class ModelRequest:
    purpose: str  # e.g. "symbol_pick"; used for cost reporting and recordings
    prompt_version: str  # e.g. "symbol_pick.v1"
    system: str
    messages: tuple[Message, ...]
    schema_name: str = ""  # empty when the request expects tool calls rather than one answer
    schema: dict[str, Any] = field(default_factory=dict, hash=False)
    tools: tuple[ToolSpec, ...] = ()
    cache_points: tuple[int, ...] = ()  # message indexes that end a cacheable prefix
    max_output_tokens: int = 2000
    effort: Effort | None = None

    def __post_init__(self) -> None:
        if not self.messages or self.messages[0].role != "user":
            raise ValueError("a request needs at least one message, and the first is the user's")
        if any(not 0 <= i < len(self.messages) for i in self.cache_points):
            raise ValueError("cache points must be indexes of messages in this request")

    @classmethod
    def single(
        cls,
        *,
        purpose: str,
        prompt_version: str,
        system: str,
        user: str,
        schema_name: str,
        schema: dict[str, Any],
        max_output_tokens: int = 2000,
        effort: Effort | None = None,
    ) -> ModelRequest:
        """One user message and a response schema: the shape every request had before ADR 0013."""
        return cls(
            purpose=purpose,
            prompt_version=prompt_version,
            system=system,
            messages=(Message("user", user),),
            schema_name=schema_name,
            schema=schema,
            max_output_tokens=max_output_tokens,
            effort=effort,
        )

    @property
    def user(self) -> str:
        """The text of the latest user message."""
        return next(m.content for m in reversed(self.messages) if m.role == "user")

    @property
    def is_single(self) -> bool:
        """One user message, no tools and no effort setting: the shape whose recording key is the
        same as before ADR 0013."""
        return len(self.messages) == 1 and not self.tools and self.effort is None

    def key(self, model: str) -> str:
        """Stable identity of a request: same inputs and model -> same recorded answer.

        A single-message request hashes exactly as it did before requests became message lists,
        so every recording made then still replays. Other requests hash every message and tool.
        `cache_points` and `max_output_tokens` are cost and size hints, never part of the key.
        """
        material: object
        if self.is_single:
            material = [
                model,
                self.prompt_version,
                self.system,
                self.messages[0].content,
                self.schema_name,
                self.schema,
            ]
        else:
            material = {
                "key_version": 2,
                "model": model,
                "prompt_version": self.prompt_version,
                "system": self.system,
                "messages": [[m.role, m.content] for m in self.messages],
                "schema_name": self.schema_name,
                "schema": self.schema,
            }
            if self.tools:
                material["tools"] = [[t.name, t.description, t.input_schema] for t in self.tools]
            if self.effort is not None:
                material["effort"] = self.effort
        return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


@dataclass(frozen=True)
class ModelResponse:
    """A reply. `input_tokens` counts input billed at the full rate; cache reads and writes are
    counted separately (`cache_*_tokens`) by transports that report them. A transport that cannot
    tell them apart counts all input in `input_tokens`."""

    text: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    replayed: bool = False
    tool_calls: tuple[ToolCall, ...] = ()
    stop_reason: StopReason = ""
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    latency_ms: int = 0  # time the live call took; 0 for a replayed answer


class Transport(Protocol):
    @property
    def model(self) -> str: ...

    def complete(self, request: ModelRequest) -> ModelResponse: ...


_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "host.docker.internal"})


def is_local_endpoint(base_url: str) -> bool:
    """A model server on this machine (e.g. Ollama) needs no API key."""
    return (urlsplit(base_url).hostname or "") in _LOCAL_HOSTS
