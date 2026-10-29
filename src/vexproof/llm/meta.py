"""OpenAI-compatible transport: the Meta Model API (Muse Spark) or a local server (Ollama, Llama).

Meta recommends the Responses API for Muse Spark; Chat Completions is available as a fallback
(`VEXPROOF_MODEL_API=chat`), and is what local servers such as Ollama support best. Both use
JSON-schema structured output. Transient failures (network, 429, 5xx) are retried with backoff;
authentication, billing and request errors are not.
"""

from __future__ import annotations

from typing import Literal

import openai
import stamina

from vexproof.llm.types import ModelError, ModelRequest, ModelResponse, is_local_endpoint

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
        try:
            return self._call(request)
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

    @stamina.retry(on=_TRANSIENT, attempts=4, timeout=180.0)
    def _call(self, request: ModelRequest) -> ModelResponse:
        if self._api == "chat":
            return self._chat(request)
        return self._responses(request)

    def _responses(self, request: ModelRequest) -> ModelResponse:
        response = self._client.responses.create(
            model=self._model,
            instructions=request.system,
            input=request.user,
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
        return ModelResponse(
            text=response.output_text,
            model=response.model or self._model,
            input_tokens=usage.input_tokens if usage else 0,
            output_tokens=usage.output_tokens if usage else 0,
        )

    def _chat(self, request: ModelRequest) -> ModelResponse:
        completion = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": request.system},
                {"role": "user", "content": request.user},
            ],
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
        return ModelResponse(
            text=completion.choices[0].message.content or "" if completion.choices else "",
            model=completion.model or self._model,
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
        )
