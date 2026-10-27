"""JSON over HTTP with explicit timeouts, retries on transient failures, and caching."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

import httpx
import stamina

from vexproof.errors import IntelError
from vexproof.intel.cache import Cache

_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
JSON = dict[str, Any] | list[Any] | str | int | float | bool | None
Body = Mapping[str, object] | None
HOUR = 3600.0
DAY = 24 * HOUR


def _retryable(exc: Exception) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in _RETRY_STATUSES
    return isinstance(exc, httpx.TransportError)


def make_client(user_agent: str, timeout_s: float) -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(timeout_s, connect=10.0),
        headers={"User-Agent": user_agent, "Accept": "application/json"},
        follow_redirects=True,
    )


class JsonHttp:
    def __init__(self, client: httpx.Client, cache: Cache | None = None) -> None:
        self._client = client
        self._cache = cache

    @staticmethod
    def _key(method: str, url: str, params: dict[str, str] | None, body: Body) -> str:
        material = json.dumps([method, url, params or {}, body], sort_keys=True)
        return hashlib.sha256(material.encode()).hexdigest()

    @stamina.retry(on=_retryable, attempts=4, timeout=60.0)
    def _send(self, method: str, url: str, params: dict[str, str] | None, body: Body) -> str:
        response = self._client.request(method, url, params=params, json=body)
        response.raise_for_status()
        return response.text

    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        body: Body = None,
        ttl_s: float | None = DAY,
    ) -> JSON:
        key = self._key(method, url, params, body)
        cached = self._cache.get(key, ttl_s) if self._cache else None
        if cached is None:
            try:
                cached = self._send(method, url, params, body)
            except httpx.HTTPError as exc:
                raise IntelError(f"{method} {url} failed: {exc}") from exc
            if self._cache:
                self._cache.set(key, cached)
        try:
            parsed: JSON = json.loads(cached)
        except json.JSONDecodeError as exc:
            raise IntelError(f"{method} {url} returned invalid JSON") from exc
        return parsed
