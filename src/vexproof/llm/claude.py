"""Claude transport: the Messages API through the Anthropic SDK (ADR 0013).

- Answers use structured outputs (`output_config.format`). Tools are strict, with automatic tool
  choice; a tool is never forced, because Opus 5.5 and Sonnet 5.5 reject a forced tool choice.
- Thinking stays on, as the current models require; a request's `effort` sets how much.
- A refusal is retried on the server with `fallbacks: "default"` (beta) unless that is turned off.
  The reply then names the model that served it, and the recording keeps that name.
- Credentials come from the SDK's own lookup: `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` or an
  `ant auth login` profile. Nothing here reads or stores a key.
- The SDK retries connection errors, 408, 409, 429 and 5xx with backoff, honouring `retry-after`.
"""

from __future__ import annotations

import time
from typing import Any

import anthropic
from anthropic.types import Message as ClaudeMessage
from anthropic.types.beta import BetaMessage

from vexproof.llm.types import ModelError, ModelRequest, ModelResponse, StopReason, ToolCall

FALLBACK_BETA = "server-side-fallback-2026-07-01"
_STOP: dict[str, StopReason] = {
    "end_turn": "end_turn",
    "stop_sequence": "end_turn",
    "max_tokens": "max_tokens",
    "tool_use": "tool_use",
    "refusal": "refusal",
}
_NO_CREDENTIALS = "set ANTHROPIC_API_KEY, or run `ant auth login`"
# Errors the SDK has already retried with backoff: 429 and the 5xx family. In SDK 2.x a 529 is
# OverloadedError and a 503 ServiceUnavailableError, separate from InternalServerError.
_UNAVAILABLE = (
    anthropic.RateLimitError,
    anthropic.InternalServerError,
    anthropic.OverloadedError,
    anthropic.ServiceUnavailableError,
    anthropic.DeadlineExceededError,
)


class ClaudeTransport:
    def __init__(
        self,
        *,
        model: str,
        timeout_s: float = 120.0,
        fallbacks: bool = True,
        max_retries: int = 4,
        client: anthropic.Anthropic | None = None,
    ) -> None:
        try:
            self._client = client or anthropic.Anthropic(timeout=timeout_s, max_retries=max_retries)
        except anthropic.AnthropicError as exc:
            raise ModelError(f"cannot set up the Claude client: {exc} ({_NO_CREDENTIALS})") from exc
        self._model = model
        self._fallbacks = fallbacks

    @property
    def model(self) -> str:
        return self._model

    def complete(self, request: ModelRequest) -> ModelResponse:
        if any(m.role == "assistant" and not m.blocks for m in request.messages):
            # An earlier Claude turn carries thinking blocks that must go back unchanged; a turn
            # rebuilt from its text alone would be an edited history. Use Message.reply().
            raise ModelError(
                "an earlier assistant turn has no content blocks; build it with Message.reply()"
            )
        started = time.perf_counter()
        try:
            message = self._create(request)
        except anthropic.AuthenticationError as exc:
            raise ModelError(
                f"the Claude API rejected the credentials ({_NO_CREDENTIALS})"
            ) from exc
        except anthropic.PermissionDeniedError as exc:
            raise ModelError(f"the Claude API denied access: {exc.message}") from exc
        except anthropic.NotFoundError as exc:
            raise ModelError(
                f"model {self._model!r} not found; run `vexproof check-model` to list the models "
                "this account can use"
            ) from exc
        except _UNAVAILABLE as exc:  # before APIStatusError, which they all subclass
            raise ModelError(f"the Claude API is unavailable after retries: {exc.message}") from exc
        except anthropic.APIStatusError as exc:
            raise ModelError(f"Claude API error {exc.status_code}: {exc.message}") from exc
        except anthropic.APIConnectionError as exc:
            raise ModelError(f"cannot reach the Claude API after retries: {exc}") from exc
        except anthropic.AnthropicError as exc:  # e.g. no credentials found at request time
            raise ModelError(f"Claude client error: {exc} ({_NO_CREDENTIALS})") from exc
        return _to_response(message, round((time.perf_counter() - started) * 1000))

    def _create(self, request: ModelRequest) -> ClaudeMessage | BetaMessage:
        params: dict[str, Any] = {
            "model": self._model,
            "max_tokens": request.max_output_tokens,
            "system": request.system,
            "messages": _messages(request),
        }
        output_config: dict[str, Any] = {}
        if request.schema:
            output_config["format"] = {"type": "json_schema", "schema": request.schema}
        if request.effort is not None:
            output_config["effort"] = request.effort
        if output_config:
            params["output_config"] = output_config
        if request.tools:
            params["tools"] = [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema,
                    "strict": True,
                }
                for t in request.tools
            ]
            params["tool_choice"] = {"type": "auto"}
        # non-streaming, so each call returns one whole message
        if self._fallbacks:
            beta: BetaMessage = self._client.beta.messages.create(
                **params, betas=[FALLBACK_BETA], fallbacks="default"
            )
            return beta
        plain: ClaudeMessage = self._client.messages.create(**params)
        return plain


_THINKING = frozenset({"thinking", "redacted_thinking"})


def _messages(request: ModelRequest) -> list[dict[str, Any]]:
    """Each message as its recorded blocks, sent back unchanged, or else as one text block.

    A cache point marks the end of a cacheable prefix. It goes on the message's last block that is
    not thinking; the blocks are copied first, so a recording is never altered.
    """
    out: list[dict[str, Any]] = []
    for i, message in enumerate(request.messages):
        blocks = [dict(b) for b in message.blocks] or [{"type": "text", "text": message.content}]
        if i in request.cache_points:
            last = next((b for b in reversed(blocks) if b.get("type") not in _THINKING), None)
            if last is not None:
                last["cache_control"] = {"type": "ephemeral"}
        out.append({"role": message.role, "content": blocks})
    return out


def _to_response(message: ClaudeMessage | BetaMessage, latency_ms: int) -> ModelResponse:
    blocks = message.content or []
    usage = message.usage
    return ModelResponse(
        text="".join(b.text for b in blocks if b.type == "text"),
        model=message.model,  # the model that served it: a fallback model after a refusal
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
        cache_read_tokens=usage.cache_read_input_tokens or 0,
        cache_write_tokens=usage.cache_creation_input_tokens or 0,
        stop_reason=_STOP.get(message.stop_reason or "", ""),
        tool_calls=tuple(
            ToolCall(b.id, b.name, dict(b.input)) for b in blocks if b.type == "tool_use"
        ),
        latency_ms=latency_ms,
        # as plain dicts, the form the API takes back; fields the API left empty are dropped
        blocks=tuple(b.model_dump(mode="json", exclude_none=True) for b in blocks),
    )


def list_claude_models(client: anthropic.Anthropic | None = None) -> list[str]:
    """Model ids this account can use."""
    try:
        client = client or anthropic.Anthropic(max_retries=1, timeout=30)
        return sorted(m.id for m in client.models.list())
    except anthropic.AnthropicError as exc:
        raise ModelError(f"could not list Claude models: {exc}") from exc
