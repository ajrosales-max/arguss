"""Central logging configuration for Arguss web and CLI entry points."""

from __future__ import annotations

import logging

from arguss.logging_filters import SecretFilter

_CONFIGURED = False


def configure_logging(level: str = "INFO") -> None:
    """Configure the arguss logger tree for structured stdout output."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s — %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    handler.addFilter(SecretFilter())

    root = logging.getLogger("arguss")
    root.setLevel(level.upper())
    root.handlers.clear()
    root.addHandler(handler)
    root.propagate = False

    _CONFIGURED = True
