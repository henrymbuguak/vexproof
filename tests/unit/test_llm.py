from __future__ import annotations

import json
from pathlib import Path

import httpx2
import openai
import pytest
from pydantic import BaseModel, ConfigDict

from tests.llm_fakes import ScriptedTransport
from vexproof.llm.budget import BudgetTransport, Usage, UsageReport
from vexproof.llm.factory import ModelConfig, build_stack, list_models
from vexproof.llm.meta import Api, MetaTransport
from vexproof.llm.recording import RecordingTransport
from vexproof.llm.structured import StructuredCaller, strict_schema
from vexproof.llm.types import (
    BudgetExceededError,
    ModelError,
    ModelOutputInvalidError,
    ModelReplayMissError,
    ModelRequest,
    is_local_endpoint,
)

BASE = "https://api.test/v1"


class Answer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    score: int = 0
    note: str | None = None


def _request(user: str = "hello", purpose: str = "test") -> ModelRequest:
    return ModelRequest(
        purpose=purpose,
        prompt_version="test.v1",
        system="system",
        user=user,
        schema_name="Answer",
        schema=strict_schema(Answer),
        max_output_tokens=100,
    )


# -- request identity and schema ---------------------------------------------------------------


def test_request_key_changes_with_every_input() -> None:
    base = _request()
    assert base.key("m") == _request().key("m")
    assert base.key("m") != base.key("other-model")
    assert base.key("m") != _request(user="changed").key("m")


def test_strict_schema_requires_everything_and_forbids_extras() -> None:
    schema = strict_schema(Answer)
    assert schema["required"] == ["name", "score", "note"]
    assert schema["additionalProperties"] is False
    assert "title" not in schema
    assert all("default" not in prop for prop in schema["properties"].values())


# -- recording ---------------------------------------------------------------------------------


def test_cache_mode_records_then_replays(tmp_path: Path) -> None:
    live = ScriptedTransport([{"name": "first"}])
    recorder = RecordingTransport(live, tmp_path, "cache")
    first = recorder.complete(_request())
    second = recorder.complete(_request())
    assert not first.replayed
    assert second.replayed
    assert second.text == first.text
    assert len(live.requests) == 1
    rows = (tmp_path / "test.jsonl").read_text().splitlines()
    assert json.loads(rows[0])["prompt_version"] == "test.v1"
    # a fresh process replays from disk without a live transport
    replay = RecordingTransport(None, tmp_path, "replay", model="fake-model")
    assert replay.model == "fake-model"
    assert replay.complete(_request()).text == first.text


def test_replay_mode_never_calls_and_misses_loudly(tmp_path: Path) -> None:
    replay = RecordingTransport(None, tmp_path, "replay", model="fake-model")
    with pytest.raises(ModelReplayMissError, match=r"test\.v1"):
        replay.complete(_request())
    # recordings of another model are not reused
    RecordingTransport(ScriptedTransport([{"name": "x"}]), tmp_path, "cache").complete(_request())
    other = RecordingTransport(None, tmp_path, "replay", model="muse-spark-1.2")
    with pytest.raises(ModelReplayMissError):
        other.complete(_request())


def test_live_mode_always_calls_and_never_records(tmp_path: Path) -> None:
    live = ScriptedTransport([{"name": "a"}, {"name": "b"}])
    recorder = RecordingTransport(live, tmp_path, "live")
    assert recorder.complete(_request()).text != recorder.complete(_request()).text
    assert not (tmp_path / "test.jsonl").exists()


def test_recording_transport_validates_arguments(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="live transport"):
        RecordingTransport(None, tmp_path, "cache")
    with pytest.raises(ValueError, match="model name"):
        RecordingTransport(None, tmp_path, "replay")


# -- budget ------------------------------------------------------------------------------------


def test_budget_counts_tokens_and_stops_before_overspending(tmp_path: Path) -> None:
    budget = BudgetTransport(ScriptedTransport(lambda _: {"name": "x"}), max_tokens=200)
    budget.complete(_request())  # 120 tokens
    budget.complete(_request(purpose="other"))  # 240: over budget, but only checked before calls
    with pytest.raises(BudgetExceededError, match="200"):
        budget.complete(_request())
    report = budget.report
    assert report.total.calls == 2
    assert report.total.input_tokens == 200
    assert report.by_purpose["test"].output_tokens == 20


def test_replayed_answers_cost_nothing(tmp_path: Path) -> None:
    recorder = RecordingTransport(ScriptedTransport([{"name": "x"}]), tmp_path, "cache")
    budget = BudgetTransport(recorder, max_tokens=10**6)
    budget.complete(_request())
    budget.complete(_request())
    total = budget.report.total
    assert (total.calls, total.replayed, total.input_tokens) == (2, 1, 100)


def test_cost_needs_both_prices() -> None:
    report = UsageReport({"x": Usage(calls=1, input_tokens=1_000_000, output_tokens=500_000)})
    assert report.cost_usd(None, 2.0) is None
    assert report.cost_usd(1.0, 2.0) == pytest.approx(2.0)


# -- structured output -------------------------------------------------------------------------


def test_structured_caller_parses_fenced_json() -> None:
    caller = StructuredCaller(
        ScriptedTransport(['```json\n{"name": "n", "score": 2, "note": null}\n```'])
    )
    answer = caller.ask(Answer, purpose="t", prompt_version="t.v1", system="s", user="u")
    assert answer == Answer(name="n", score=2)


def test_structured_caller_repairs_once() -> None:
    live = ScriptedTransport(["not json", {"name": "fixed", "score": 1, "note": None}])
    answer = StructuredCaller(live).ask(
        Answer, purpose="t", prompt_version="t.v1", system="s", user="u"
    )
    assert answer.name == "fixed"
    assert "previous reply was not valid" in live.requests[1].user


def test_structured_caller_gives_up_after_one_repair() -> None:
    live = ScriptedTransport(["nope", {"name": "x", "unexpected": True}])
    with pytest.raises(ModelOutputInvalidError, match="Answer"):
        StructuredCaller(live).ask(Answer, purpose="t", prompt_version="t.v1", system="s", user="u")


# -- factory -----------------------------------------------------------------------------------


def _config(tmp_path: Path, **changes: object) -> ModelConfig:
    values: dict[str, object] = {
        "api_key": None,
        "base_url": BASE,
        "model": "muse-spark-1.1",
        "recordings_dir": tmp_path,
    }
    values.update(changes)
    return ModelConfig(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("url", "local"),
    [
        ("http://localhost:11434/v1", True),
        ("http://127.0.0.1:11434/v1", True),
        ("http://[::1]:11434/v1", True),
        ("http://host.docker.internal:11434/v1", True),
        ("https://api.meta.ai/v1", False),
        ("https://localhost.example.com/v1", False),
    ],
)
def test_is_local_endpoint(url: str, local: bool) -> None:
    assert is_local_endpoint(url) is local


def test_local_server_needs_no_key(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        base_url="http://localhost:11434/v1",
        model="llama3.1:8b",
        api="chat",
        timeout_s=600.0,
        workers=1,
    )
    assert config.ready
    stack = build_stack(config)
    assert (stack.label, stack.workers) == ("llama3.1:8b", 1)


def test_build_stack_needs_a_key_unless_replaying(tmp_path: Path) -> None:
    with pytest.raises(ModelError, match="MODEL_API_KEY"):
        build_stack(_config(tmp_path))
    replay = build_stack(_config(tmp_path, mode="replay"))
    assert replay.label == "muse-spark-1.1"
    live = build_stack(_config(tmp_path, api_key="k"))
    assert live.label == "muse-spark-1.1"


def _client(*responses: httpx2.Response) -> tuple[openai.OpenAI, list[httpx2.Request]]:
    """An OpenAI SDK client whose HTTP layer replays `responses` in order and keeps requests.

    The SDK uses its own HTTP stack (httpx2), so respx cannot see it; a mock transport can.
    """
    queue = list(responses)
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return queue.pop(0)

    http = httpx2.Client(transport=httpx2.MockTransport(handler))
    return openai.OpenAI(api_key="k", base_url=BASE, max_retries=0, http_client=http), seen


def _model(model_id: str) -> dict[str, object]:
    return {"id": model_id, "object": "model", "created": 0, "owned_by": "meta"}


def test_list_models() -> None:
    body = {"object": "list", "data": [_model("muse-spark-1.2"), _model("muse-spark-1.1")]}
    client, seen = _client(httpx2.Response(200, json=body))
    assert list_models("k", BASE, client) == ["muse-spark-1.1", "muse-spark-1.2"]
    assert str(seen[0].url) == f"{BASE}/models"
    client, _ = _client(httpx2.Response(401, json={"error": {"message": "bad key"}}))
    with pytest.raises(ModelError, match="could not list models"):
        list_models("k", BASE, client)


# -- Meta transport over HTTP ------------------------------------------------------------------

RESPONSES_BODY = {
    "id": "resp_1",
    "object": "response",
    "created_at": 0,
    "model": "muse-spark-1.1",
    "status": "completed",
    "parallel_tool_calls": False,
    "tool_choice": "auto",
    "tools": [],
    "output": [
        {
            "type": "message",
            "id": "msg_1",
            "status": "completed",
            "role": "assistant",
            "content": [{"type": "output_text", "text": '{"name": "r"}', "annotations": []}],
        }
    ],
    "usage": {
        "input_tokens": 11,
        "output_tokens": 7,
        "total_tokens": 18,
        "input_tokens_details": {"cached_tokens": 0},
        "output_tokens_details": {"reasoning_tokens": 0},
    },
}
CHAT_BODY = {
    "id": "c1",
    "object": "chat.completion",
    "created": 0,
    "model": "muse-spark-1.1",
    "choices": [
        {
            "index": 0,
            "finish_reason": "stop",
            "message": {"role": "assistant", "content": '{"name": "c"}'},
        }
    ],
    "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
}


def _meta(
    *responses: httpx2.Response, api: Api = "responses"
) -> tuple[MetaTransport, list[httpx2.Request]]:
    client, seen = _client(*responses)
    transport = MetaTransport(
        api_key="k", base_url=BASE, model="muse-spark-1.1", api=api, client=client
    )
    return transport, seen


def test_meta_responses_api_sends_strict_schema() -> None:
    meta, seen = _meta(httpx2.Response(200, json=RESPONSES_BODY))
    response = meta.complete(_request())
    assert (response.text, response.input_tokens, response.output_tokens) == (
        '{"name": "r"}',
        11,
        7,
    )
    assert str(seen[0].url) == f"{BASE}/responses"
    sent = json.loads(seen[0].content)
    assert sent["store"] is False
    assert sent["instructions"] == "system"
    assert sent["text"]["format"]["strict"] is True
    assert sent["text"]["format"]["name"] == "Answer"
    assert seen[0].headers["authorization"] == "Bearer k"


def test_meta_chat_api() -> None:
    meta, seen = _meta(httpx2.Response(200, json=CHAT_BODY), api="chat")
    response = meta.complete(_request())
    assert (response.text, response.input_tokens) == ('{"name": "c"}', 5)
    assert str(seen[0].url) == f"{BASE}/chat/completions"
    sent = json.loads(seen[0].content)
    assert sent["response_format"]["type"] == "json_schema"
    assert sent["messages"][0] == {"role": "system", "content": "system"}


def test_meta_retries_transient_errors() -> None:
    meta, seen = _meta(
        httpx2.Response(429, json={"error": {"message": "slow down"}}),
        httpx2.Response(200, json=RESPONSES_BODY),
    )
    assert meta.complete(_request()).text == '{"name": "r"}'
    assert len(seen) == 2


@pytest.mark.parametrize(
    ("status", "message"),
    [
        (401, "rejected the API key"),
        (403, "denied access"),
        (404, "check-model"),
        (402, "billing"),
        (400, "Model API error 400"),
    ],
)
def test_meta_error_messages(status: int, message: str) -> None:
    meta, seen = _meta(httpx2.Response(status, json={"error": {"message": "nope"}}))
    with pytest.raises(ModelError, match=message):
        meta.complete(_request())
    assert len(seen) == 1  # not retried


OLLAMA = "http://localhost:11434/v1"
# The shape Ollama's OpenAI-compatible /v1/chat/completions returns
OLLAMA_CHAT_BODY = {
    "id": "chatcmpl-123",
    "object": "chat.completion",
    "created": 1761700000,
    "model": "llama3.1:8b",
    "system_fingerprint": "fp_ollama",
    "choices": [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": '{"name": "local", "score": 1, "note": null}',
            },
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 420, "completion_tokens": 25, "total_tokens": 445},
}


def _local(*responses: httpx2.Response) -> tuple[MetaTransport, list[httpx2.Request]]:
    queue = list(responses)
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        reply = queue.pop(0)
        if reply.status_code == 599:  # stand-in for "nothing is listening"
            raise httpx2.ConnectError("connection refused", request=request)
        return reply

    http = httpx2.Client(transport=httpx2.MockTransport(handler))
    client = openai.OpenAI(api_key="local", base_url=OLLAMA, max_retries=0, http_client=http)
    transport = MetaTransport(
        api_key="local", base_url=OLLAMA, model="llama3.1:8b", api="chat", client=client
    )
    return transport, seen


def test_ollama_chat_structured_output() -> None:
    meta, seen = _local(httpx2.Response(200, json=OLLAMA_CHAT_BODY))
    caller = StructuredCaller(meta)
    answer = caller.ask(Answer, purpose="t", prompt_version="t.v1", system="s", user="u")
    assert answer == Answer(name="local", score=1)
    assert str(seen[0].url) == f"{OLLAMA}/chat/completions"
    sent = json.loads(seen[0].content)
    assert sent["model"] == "llama3.1:8b"
    assert sent["response_format"]["json_schema"]["strict"] is True


def test_local_server_errors_say_what_to_do() -> None:
    down, seen = _local(*[httpx2.Response(599)] * 4)
    with pytest.raises(ModelError, match=r"localhost:11434.*ollama serve"):
        down.complete(_request())
    assert len(seen) == 4
    missing, _ = _local(httpx2.Response(404, json={"error": {"message": "model not found"}}))
    with pytest.raises(ModelError, match=r"ollama pull llama3\.1:8b"):
        missing.complete(_request())


def test_meta_gives_up_on_persistent_server_errors() -> None:
    meta, seen = _meta(*[httpx2.Response(503, json={"error": {"message": "down"}})] * 4)
    with pytest.raises(ModelError, match="unavailable after retries"):
        meta.complete(_request())
    assert len(seen) == 4
