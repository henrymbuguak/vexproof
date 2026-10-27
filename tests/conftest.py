"""Fixtures shared by every test. Tests never touch the network unless marked `network`."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
import stamina


@pytest.fixture(autouse=True)
def _no_retry_waits() -> Iterator[None]:
    """Keep retry behaviour but skip the backoff sleeps."""
    stamina.set_testing(True, attempts=4)
    yield
    stamina.set_testing(False)
