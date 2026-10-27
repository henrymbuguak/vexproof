from __future__ import annotations

import io
import sys

import pytest
import structlog
from stamina.instrumentation import RetryDetails, get_on_retry_hooks, set_on_retry_hooks

from vexproof.logging import _log_retry, configure_logging


def test_retry_log_omits_request_body(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(json_output=True)
    try:
        assert get_on_retry_hooks() == (_log_retry,)
        _log_retry(
            RetryDetails(
                name="send",
                args=(
                    object(),
                    "POST",
                    "https://osv.test/v1/querybatch",
                    None,
                    {"secret": "inventory"},
                ),
                kwargs={},
                retry_num=1,
                wait_for=0.5,
                waited_so_far=0.0,
                caused_by=ConnectionError("down"),
            )
        )
        err = capsys.readouterr().err
        assert '"url": "https://osv.test/v1/querybatch"' in err
        assert "inventory" not in err
    finally:
        set_on_retry_hooks(None)


def test_logging_survives_a_replaced_and_closed_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    configure_logging(json_output=True)
    temporary = io.StringIO()
    monkeypatch.setattr(sys, "stderr", temporary)
    structlog.get_logger("t").warning("first")
    temporary.close()
    replacement = io.StringIO()
    monkeypatch.setattr(sys, "stderr", replacement)
    structlog.get_logger("t").warning("second")
    assert '"event": "second"' in replacement.getvalue()
