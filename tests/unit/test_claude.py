"""ClaudeTransport through the real Anthropic SDK, with HTTP replaced by a scripted handler."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import anthropic
import httpx2
import pytest
from pydantic import BaseModel, ConfigDict

from vexproof.llm.claude import FALLBACK_BETA, ClaudeTransport, list_claude_models
from vexproof.llm.factory import ModelConfig, build_stack
from vexproof.llm.recording import RecordingTransport
from vexproof.llm.structured import StructuredCaller, strict_schema
from vexproof.llm.types import (
    Message,
    ModelError,
    ModelRefusedError,
    ModelRequest,
    ModelTruncatedError,
    ToolSpec,
)

BASE = "https://api.anthropic.test"


class Answer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str


def _message(
    text: str = '{"name": "claude"}',
    *,
    stop: str = "end_turn",
    model: str = "claude-opus-5-5",
    content: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content if content is not None else [{"type": "text", "text": text}],
        "stop_reason": stop,
        "stop_sequence": None,
        "usage": {
            "input_tokens": 30,
            "output_tokens": 9,
            "cache_read_input_tokens": 1200,
            "cache_creation_input_tokens": 40,
        },
    }


def _claude(
    *replies: httpx2.Response, fallbacks: bool = True
) -> tuple[ClaudeTransport, list[httpx2.Request]]:
    queue = list(replies)
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return queue.pop(0)

    client = anthropic.Anthropic(
        api_key="test-key",
        base_url=BASE,
        max_retries=0,
        http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(handler)),
    )
    return ClaudeTransport(model="claude-opus-5-5", fallbacks=fallbacks, client=client), seen


def _request(**changes: Any) -> ModelRequest:
    base = ModelRequest.single(
        purpose="symbol_pick",
        prompt_version="symbol_pick.v1",
        system="You are a vulnerability analyst.",
        user="<advisory>...</advisory>",
        schema_name="Answer",
        schema=strict_schema(Answer),
        max_output_tokens=16_000,
    )
    return dataclasses.replace(base, **changes)


def _body(request: httpx2.Request) -> dict[str, Any]:
    body: dict[str, Any] = json.loads(request.content)
    return body


# -- what goes over the wire -------------------------------------------------------------------


def test_a_pick_uses_structured_outputs_effort_and_the_fallback_beta() -> None:
    claude, seen = _claude(httpx2.Response(200, json=_message()))
    answer = StructuredCaller(claude, effort="high").ask(
        Answer, purpose="symbol_pick", prompt_version="v1", system="sys", user="pick one"
    )
    assert answer == Answer(name="claude")
    (sent,) = seen
    assert sent.url.path == "/v1/messages"
    assert FALLBACK_BETA in sent.headers["anthropic-beta"]
    body = _body(sent)
    assert body["model"] == "claude-opus-5-5"
    assert body["system"] == "sys"
    assert body["messages"] == [{"role": "user", "content": [{"type": "text", "text": "pick one"}]}]
    assert body["output_config"] == {
        "format": {"type": "json_schema", "schema": strict_schema(Answer)},
        "effort": "high",
    }
    assert body["fallbacks"] == "default"
    assert "tool_choice" not in body
    assert "thinking" not in body  # thinking stays on: the current models refuse to turn it off


def test_the_response_keeps_tokens_cache_counts_stop_reason_and_latency() -> None:
    claude, _ = _claude(httpx2.Response(200, json=_message()))
    response = claude.complete(_request())
    assert (response.text, response.model, response.stop_reason) == (
        '{"name": "claude"}',
        "claude-opus-5-5",
        "end_turn",
    )
    assert (response.input_tokens, response.output_tokens) == (30, 9)
    assert (response.cache_read_tokens, response.cache_write_tokens) == (1200, 40)
    assert response.latency_ms >= 0


def test_without_fallbacks_the_plain_endpoint_is_used() -> None:
    claude, seen = _claude(httpx2.Response(200, json=_message()), fallbacks=False)
    claude.complete(_request(effort=None))
    body = _body(seen[0])
    assert "fallbacks" not in body
    assert FALLBACK_BETA not in seen[0].headers.get("anthropic-beta", "")
    assert body["output_config"] == {"format": {"type": "json_schema", "schema": _request().schema}}


def test_cache_points_mark_their_message() -> None:
    turns = (Message("user", "stable context"), Message("user", "the question"))
    claude, seen = _claude(httpx2.Response(200, json=_message()))
    claude.complete(_request(messages=turns, cache_points=(0,)))
    first, second = _body(seen[0])["messages"]
    assert first["content"][0]["cache_control"] == {"type": "ephemeral"}
    assert "cache_control" not in second["content"][0]


def test_tools_are_strict_with_automatic_choice_and_calls_come_back() -> None:
    tool = ToolSpec("search", "Find a new candidate path.", {"type": "object"})
    reply = _message(
        stop="tool_use",
        content=[
            {"type": "text", "text": "Searching again."},
            {"type": "tool_use", "id": "toolu_1", "name": "search", "input": {"avoid": ["a.b"]}},
        ],
    )
    claude, seen = _claude(httpx2.Response(200, json=reply))
    response = claude.complete(_request(tools=(tool,), schema={}, schema_name=""))
    body = _body(seen[0])
    assert body["tools"] == [
        {
            "name": "search",
            "description": "Find a new candidate path.",
            "input_schema": {"type": "object"},
            "strict": True,
        }
    ]
    assert body["tool_choice"] == {"type": "auto"}  # never forced
    assert "output_config" not in body
    assert response.stop_reason == "tool_use"
    assert [(c.id, c.name, c.input) for c in response.tool_calls] == [
        ("toolu_1", "search", {"avoid": ["a.b"]})
    ]


def test_conversations_with_assistant_turns_are_refused_until_thinking_is_kept() -> None:
    claude, seen = _claude()
    turns = (Message("user", "q"), Message("assistant", "a"), Message("user", "q2"))
    with pytest.raises(ModelError, match="earlier assistant turns"):
        claude.complete(_request(messages=turns))
    assert seen == []


# -- stop reasons are typed failures, never answers --------------------------------------------


def test_a_refusal_is_a_typed_failure_and_is_not_repaired() -> None:
    claude, seen = _claude(httpx2.Response(200, json=_message("", stop="refusal")))
    with pytest.raises(ModelRefusedError, match="declined"):
        StructuredCaller(claude).ask(Answer, purpose="p", prompt_version="v", system="s", user="u")
    assert len(seen) == 1  # no repair retry


def test_a_cut_off_reply_is_a_typed_failure_and_is_not_repaired() -> None:
    claude, seen = _claude(httpx2.Response(200, json=_message('{"na', stop="max_tokens")))
    with pytest.raises(ModelTruncatedError, match="output limit"):
        StructuredCaller(claude).ask(Answer, purpose="p", prompt_version="v", system="s", user="u")
    assert len(seen) == 1


def test_a_fallback_answer_is_recorded_under_the_model_that_served_it(tmp_path: Path) -> None:
    served = _message(model="claude-opus-4-8")
    claude, _ = _claude(httpx2.Response(200, json=served))
    RecordingTransport(claude, tmp_path, "cache").complete(_request())
    (row,) = [
        json.loads(line) for line in (tmp_path / "symbol_pick.jsonl").read_text().splitlines()
    ]
    assert (row["response"]["model"], row["response"]["served_by"]) == (
        "claude-opus-5-5",
        "claude-opus-4-8",
    )
    replayed = RecordingTransport(None, tmp_path, "replay", model="claude-opus-5-5").complete(
        _request()
    )
    assert replayed.model == "claude-opus-4-8"


# -- errors ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "error_type", "message"),
    [
        (401, "authentication_error", "ANTHROPIC_API_KEY"),
        (403, "permission_error", "denied access"),
        (404, "not_found_error", "check-model"),
        (400, "invalid_request_error", "Claude API error 400"),
        (429, "rate_limit_error", "unavailable after retries"),
        (529, "overloaded_error", "unavailable after retries"),
        (503, "api_error", "unavailable after retries"),
        (500, "api_error", "unavailable after retries"),
    ],
)
def test_errors_say_what_to_do(status: int, error_type: str, message: str) -> None:
    error = {"type": "error", "error": {"type": error_type, "message": "nope"}}
    claude, _ = _claude(httpx2.Response(status, json=error))
    with pytest.raises(ModelError, match=message):
        claude.complete(_request())


def test_an_unreachable_api_is_a_model_error() -> None:
    def refuse(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("connection refused", request=request)

    client = anthropic.Anthropic(
        api_key="test-key",
        base_url=BASE,
        max_retries=0,
        http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(refuse)),
    )
    with pytest.raises(ModelError, match="cannot reach the Claude API"):
        ClaudeTransport(model="claude-opus-5-5", client=client).complete(_request())


# -- configuration ------------------------------------------------------------------------------


def test_effort_is_part_of_a_requests_identity() -> None:
    plain = _request()
    assert plain.is_single
    high = _request(effort="high")
    assert not high.is_single  # Claude requests never share keys with old Muse recordings
    assert high.key("m") != plain.key("m") != _request(effort="low").key("m")


def test_the_stack_builds_claude_without_a_model_api_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")  # the SDK's own lookup
    config = ModelConfig(
        api_key=None,
        base_url="https://api.meta.ai/v1",  # ignored for Claude
        model="claude-opus-5-5",
        api="anthropic",
        effort="high",
        recordings_dir=tmp_path,
    )
    assert config.ready
    assert not config.local
    stack = build_stack(config)
    assert stack.label == "claude-opus-5-5"


def test_listing_models() -> None:
    page = {
        "data": [
            {
                "type": "model",
                "id": "claude-sonnet-5-5",
                "display_name": "S",
                "created_at": "2026-01-01T00:00:00Z",
            },
            {
                "type": "model",
                "id": "claude-opus-5-5",
                "display_name": "O",
                "created_at": "2026-01-01T00:00:00Z",
            },
        ],
        "has_more": False,
        "first_id": "claude-sonnet-5-5",
        "last_id": "claude-opus-5-5",
    }
    client = anthropic.Anthropic(
        api_key="test-key",
        base_url=BASE,
        max_retries=0,
        http_client=anthropic.DefaultHttpxClient(
            transport=httpx2.MockTransport(lambda _: httpx2.Response(200, json=page))
        ),
    )
    assert list_claude_models(client) == ["claude-opus-5-5", "claude-sonnet-5-5"]
