from __future__ import annotations

from pathlib import Path

from vexproof.intel.cache import Cache


def test_ttl_expiry_and_any_age(tmp_path: Path) -> None:
    now = [1000.0]
    cache = Cache(tmp_path / "c.sqlite3", clock=lambda: now[0])
    cache.set("k", "v1")
    assert cache.get("k", ttl_s=10) == "v1"
    now[0] += 11
    assert cache.get("k", ttl_s=10) is None
    assert cache.get("k", ttl_s=None) == "v1"
    cache.set("k", "v2")
    assert cache.get("k", ttl_s=10) == "v2"
    assert cache.get("missing", ttl_s=None) is None
    cache.close()
