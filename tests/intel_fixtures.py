"""Fixtures for tests that exercise the intel stage: a temp cache, an HTTP client, mocked services.

Imported by the `conftest.py` of the test packages that need them.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import respx

from tests.helpers import EPSS, FIXTURES, KEV, OSV, fixture_json
from vexproof.intel.cache import Cache
from vexproof.intel.http import JsonHttp


@pytest.fixture
def cache(tmp_path: Path) -> Iterator[Cache]:
    c = Cache(tmp_path / "cache.sqlite3")
    yield c
    c.close()


@pytest.fixture
def http(cache: Cache) -> Iterator[JsonHttp]:
    with httpx.Client() as client:
        yield JsonHttp(client, cache)


@pytest.fixture
def mocked_services() -> Iterator[respx.MockRouter]:
    """Mock OSV, KEV and EPSS with the synthetic fixtures."""
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{OSV}/v1/querybatch").respond(json=fixture_json("osv/querybatch.json"))
        router.post(f"{OSV}/v1/query").respond(json=fixture_json("osv/query-page-2.json"))
        for record in (FIXTURES / "osv").glob("[GP]*.json"):
            router.get(f"{OSV}/v1/vulns/{record.stem}").respond(
                json=fixture_json(f"osv/{record.name}")
            )
        router.get(KEV).respond(json=fixture_json("kev.json"))
        router.get(EPSS).respond(json=fixture_json("epss.json"))
        yield router
