"""A small SQLite key-value cache with per-read TTL.

The eval reads from this cache so results are reproducible; set ttl_s=None to accept any age.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable
from pathlib import Path


class Cache:
    def __init__(self, path: Path, clock: Callable[[], float] = time.time) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS entries (key TEXT PRIMARY KEY, stored_at REAL, value TEXT)"
        )
        self._clock = clock

    def get(self, key: str, ttl_s: float | None) -> str | None:
        row = self._conn.execute(
            "SELECT stored_at, value FROM entries WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        stored_at, value = row
        if ttl_s is not None and self._clock() - float(stored_at) > ttl_s:
            return None
        return str(value)

    def set(self, key: str, value: str) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO entries (key, stored_at, value) VALUES (?, ?, ?)",
                (key, self._clock(), value),
            )

    def close(self) -> None:
        self._conn.close()
