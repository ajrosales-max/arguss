"""Shared logging utilities for the Arguss scan pipeline."""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager


@contextmanager
def log_timing(
    logger: logging.Logger,
    operation: str,
    *,
    log_start: bool = False,
    **context: object,
) -> Iterator[None]:
    """Log elapsed time on success; log exception with timing on failure.

    By default emits a single completion line. Set ``log_start=True`` for a
    matching "started" line (two lines total).
    """
    start = time.monotonic()
    if log_start:
        logger.info("%s started", operation, extra=context)
    try:
        yield
    except Exception:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.exception(
            "%s failed",
            operation,
            extra={**context, "elapsed_ms": elapsed_ms},
        )
        raise
    else:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "%s completed",
            operation,
            extra={**context, "elapsed_ms": elapsed_ms},
        )
