"""A small SQLite key-value cache with per-read TTL, safe to share between threads.

The eval reads from this cache so results are reproducible; set ttl_s=None to accept any age.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path


class Cache:
    def __init__(self, path: Path, clock: Callable[[], float] = time.time) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS entries (key TEXT PRIMARY KEY, stored_at REAL, value TEXT)"
        )
        self._clock = clock

    def get(self, key: str, ttl_s: float | None) -> str | None:
        with self._lock:
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
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO entries (key, stored_at, value) VALUES (?, ?, ?)",
                (key, self._clock(), value),
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()
