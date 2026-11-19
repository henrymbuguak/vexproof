"""OpenAI-compatible transport: the Meta Model API (Muse Spark) or a local server (Ollama, Llama).

Meta recommends the Responses API for Muse Spark; Chat Completions is available as a fallback
(`VEXPROOF_MODEL_API=chat`), and is what local servers such as Ollama support best. Both use
JSON-schema structured output. Transient failures (network, 429, 5xx) are retried with backoff;
authentication, billing and request errors are not.
"""

from __future__ import annotations

import dataclasses
import time
from typing import Any, Literal

import openai
import stamina

from vexproof.llm.types import (
    ModelError,
    ModelRequest,
    ModelResponse,
    StopReason,
    is_local_endpoint,
)

Api = Literal["responses", "chat"]
_TRANSIENT = (
    openai.APIConnectionError,
    openai.APITimeoutError,
    openai.RateLimitError,
    openai.InternalServerError,
)


class MetaTransport:
    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model: str,
        api: Api = "responses",
        timeout_s: float = 120.0,
        client: openai.OpenAI | None = None,
    ) -> None:
        self._client = client or openai.OpenAI(
            api_key=api_key, base_url=base_url, timeout=timeout_s, max_retries=0
        )
        self._model = model
        self._api = api
        self._base_url = base_url
        self._local = is_local_endpoint(base_url)

    @property
    def model(self) -> str:
        return self._model

    def complete(self, request: ModelRequest) -> ModelResponse:
        if request.tools:
            raise ModelError("this OpenAI-compatible transport does not support tool calls yet")
        started = time.perf_counter()
        try:
            response = self._call(request)
        except openai.AuthenticationError as exc:
            raise ModelError("the Model API rejected the API key (check MODEL_API_KEY)") from exc
        except openai.PermissionDeniedError as exc:
            raise ModelError(f"the Model API denied access: {exc.message}") from exc
        except openai.NotFoundError as exc:
            hint = f" (or `ollama pull {self._model}`)" if self._local else ""
            raise ModelError(
                f"model {self._model!r} or endpoint not found; run `vexproof check-model` "
                f"to list available models{hint}"
            ) from exc
        except _TRANSIENT as exc:  # before APIStatusError: 429 and 5xx errors subclass it
            hint = " Is the local model server running (`ollama serve`)?" if self._local else ""
            raise ModelError(
                f"Model API at {self._base_url} unavailable after retries: {exc}.{hint}"
            ) from exc
        except openai.APIStatusError as exc:
            hint = " (billing or credits?)" if exc.status_code == 402 else ""  # noqa: PLR2004
            raise ModelError(f"Model API error {exc.status_code}{hint}: {exc.message}") from exc
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        return dataclasses.replace(response, latency_ms=elapsed_ms)

    @stamina.retry(on=_TRANSIENT, attempts=4, timeout=180.0)
    def _call(self, request: ModelRequest) -> ModelResponse:
        if not request.schema:
            raise ModelError("this OpenAI-compatible transport needs a response schema")
        if self._api == "chat":
            return self._chat(request)
        return self._responses(request)

    def _responses(self, request: ModelRequest) -> ModelResponse:
        # one user message goes as a plain string, exactly as before requests had message lists
        conversation: str | list[Any] = (
            request.user
            if request.is_single
            else [{"role": m.role, "content": m.content} for m in request.messages]
        )
        response = self._client.responses.create(
            model=self._model,
            instructions=request.system,
            input=conversation,
            max_output_tokens=request.max_output_tokens,
            store=False,
            text={
                "format": {
                    "type": "json_schema",
                    "name": request.schema_name,
                    "schema": request.schema,
                    "strict": True,
                }
            },
        )
        usage = response.usage
        incomplete = response.incomplete_details.reason if response.incomplete_details else None
        return ModelResponse(
            text=response.output_text,
            model=response.model or self._model,
            input_tokens=usage.input_tokens if usage else 0,
            output_tokens=usage.output_tokens if usage else 0,
            stop_reason=_RESPONSES_STOP.get(incomplete or response.status or "", ""),
        )

    def _chat(self, request: ModelRequest) -> ModelResponse:
        messages: list[Any] = [
            {"role": "system", "content": request.system},
            *({"role": m.role, "content": m.content} for m in request.messages),
        ]
        completion = self._client.chat.completions.create(
            model=self._model,
            messages=messages,
            max_completion_tokens=request.max_output_tokens,
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": request.schema_name,
                    "schema": request.schema,
                    "strict": True,
                },
            },
        )
        usage = completion.usage
        choice = completion.choices[0] if completion.choices else None
        return ModelResponse(
            text=choice.message.content or "" if choice else "",
            model=completion.model or self._model,
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
            stop_reason=_CHAT_STOP.get(choice.finish_reason, "") if choice else "",
        )


# How each API says why a reply ended, in the shared vocabulary of `StopReason`. Cache tokens are
# not split out here: local servers do not report them, and input_tokens keeps its old meaning.
_RESPONSES_STOP: dict[str, StopReason] = {
    "completed": "end_turn",
    "max_output_tokens": "max_tokens",
    "content_filter": "refusal",
}
_CHAT_STOP: dict[str, StopReason] = {
    "stop": "end_turn",
    "length": "max_tokens",
    "tool_calls": "tool_use",
    "function_call": "tool_use",
    "content_filter": "refusal",
}
