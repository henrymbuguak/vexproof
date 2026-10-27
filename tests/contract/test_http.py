from __future__ import annotations

import httpx
import pytest
import respx

from vexproof.errors import IntelError
from vexproof.intel.http import JsonHttp


@respx.mock
def test_retries_transient_status_then_succeeds(http: JsonHttp) -> None:
    route = respx.get("https://svc.test/x").mock(
        side_effect=[httpx.Response(503), httpx.Response(429), httpx.Response(200, json={"ok": 1})]
    )
    assert http.request("GET", "https://svc.test/x") == {"ok": 1}
    assert route.call_count == 3


@respx.mock
def test_does_not_retry_client_errors(http: JsonHttp) -> None:
    route = respx.get("https://svc.test/x").respond(404)
    with pytest.raises(IntelError, match="404"):
        http.request("GET", "https://svc.test/x")
    assert route.call_count == 1


@respx.mock
def test_retries_transport_errors_then_gives_up(http: JsonHttp) -> None:
    route = respx.get("https://svc.test/x").mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(IntelError, match="down"):
        http.request("GET", "https://svc.test/x")
    assert route.call_count == 4


@respx.mock
def test_second_call_served_from_cache(http: JsonHttp) -> None:
    route = respx.post("https://svc.test/q").respond(json={"n": 1})
    first = http.request("POST", "https://svc.test/q", body={"a": 1})
    second = http.request("POST", "https://svc.test/q", body={"a": 1})
    assert first == second == {"n": 1}
    assert route.call_count == 1
    http.request("POST", "https://svc.test/q", body={"a": 2})
    assert route.call_count == 2


@respx.mock
def test_invalid_json_raises(http: JsonHttp) -> None:
    respx.get("https://svc.test/x").respond(text="<html>")
    with pytest.raises(IntelError, match="invalid JSON"):
        http.request("GET", "https://svc.test/x")
