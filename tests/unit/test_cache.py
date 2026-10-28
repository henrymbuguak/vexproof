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


def test_concurrent_reads_and_writes(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor

    cache = Cache(tmp_path / "c.sqlite3")

    def work(i: int) -> str | None:
        cache.set(f"k{i}", f"v{i}")
        return cache.get(f"k{i}", ttl_s=None)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(work, range(200)))
    assert results == [f"v{i}" for i in range(200)]
    cache.close()
