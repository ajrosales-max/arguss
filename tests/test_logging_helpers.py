"""Tests for log_timing helper."""

from __future__ import annotations

import logging

import pytest

from arguss.logging_helpers import log_timing


def test_log_timing_emits_start_and_complete(caplog: pytest.LogCaptureFixture) -> None:
    """log_timing emits two INFO records with elapsed_ms on completion."""
    logger = logging.getLogger("test.timing")
    with caplog.at_level(logging.INFO, logger="test.timing"), log_timing(logger, "scan", mode="A"):
        pass

    messages = [r.getMessage() for r in caplog.records]
    assert not any("scan started" in m for m in messages)
    assert any("scan completed" in m for m in messages)
    completed = [r for r in caplog.records if "completed" in r.getMessage()]
    assert completed
    assert hasattr(completed[-1], "elapsed_ms")
    assert isinstance(completed[-1].elapsed_ms, int)


def test_log_timing_logs_exception_on_failure(caplog: pytest.LogCaptureFixture) -> None:
    """log_timing logs at ERROR level when the wrapped block raises."""
    logger = logging.getLogger("test.timing.fail")
    with (
        caplog.at_level(logging.INFO, logger="test.timing.fail"),
        pytest.raises(RuntimeError),
        log_timing(logger, "scan", mode="B"),
    ):
        raise RuntimeError("boom")

    assert any(r.levelno == logging.ERROR for r in caplog.records)
    assert any("scan failed" in r.getMessage() for r in caplog.records)
