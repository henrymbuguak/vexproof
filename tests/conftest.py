"""Fixtures shared by every test. Tests never touch the network unless marked `network`."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
import stamina
import structlog
from stamina.instrumentation import set_on_retry_hooks


@pytest.fixture(autouse=True)
def _no_retry_waits() -> Iterator[None]:
    """Keep retry behaviour but skip the backoff sleeps."""
    stamina.set_testing(True, attempts=4)
    yield
    stamina.set_testing(False)


@pytest.fixture(autouse=True)
def _fresh_logging_state() -> Iterator[None]:
    """Logging and retry hooks are process-wide; reset them so no test leaks into the next."""
    structlog.reset_defaults()
    yield
    structlog.reset_defaults()
    set_on_retry_hooks(None)
