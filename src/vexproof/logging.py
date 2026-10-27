"""Structured logging. Human-readable on a terminal, JSON lines when asked (CI, eval)."""

from __future__ import annotations

import logging
import sys

import structlog
from stamina.instrumentation import RetryDetails, set_on_retry_hooks

_log = structlog.get_logger("vexproof.http")


def _log_retry(details: RetryDetails) -> None:
    """Log retries without request bodies, which can contain a private package inventory."""
    method, url = (*details.args[1:3], "?", "?")[:2]
    _log.warning(
        "http_retry",
        method=method,
        url=url,
        attempt=details.retry_num,
        wait_s=round(details.wait_for, 2),
        cause=type(details.caused_by).__name__,
    )


def _stderr_logger(*_: object) -> structlog.PrintLogger:
    """Resolve sys.stderr when each log line is written, not once at configuration.

    Test runners and some hosts swap sys.stderr for a temporary stream and close it later;
    a logger holding the old stream would then crash with "I/O operation on closed file".
    """
    return structlog.PrintLogger(file=sys.stderr)


def configure_logging(*, json_output: bool = False, level: int = logging.INFO) -> None:
    renderer: structlog.typing.Processor = (
        structlog.processors.JSONRenderer()
        if json_output
        else structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=_stderr_logger,
        cache_logger_on_first_use=False,
    )
    set_on_retry_hooks([_log_retry])
