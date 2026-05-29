"""Tests that SecretFilter redacts PATs from log output."""

from __future__ import annotations

import logging

import pytest

from arguss.logging_filters import SecretFilter


def _logger_with_filter(name: str = "test.scrub") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.handlers.clear()
    logger.filters.clear()
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addFilter(SecretFilter())
    if not logger.handlers:
        logger.addHandler(logging.StreamHandler())
    return logger


def test_classic_pat_redacted(caplog: pytest.LogCaptureFixture) -> None:
    """A ghp_-prefixed PAT in a log message is redacted."""

    logger = _logger_with_filter("test.classic")
    fake_pat = "ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD"
    with caplog.at_level(logging.INFO, logger="test.classic"):
        logger.info("using token %s for auth", fake_pat)

    for record in caplog.records:
        message = record.getMessage()
        assert fake_pat not in message
        assert "<REDACTED_PAT>" in message


def test_fine_grained_pat_redacted(caplog: pytest.LogCaptureFixture) -> None:
    """A github_pat_-prefixed PAT in a log message is redacted."""
    logger = _logger_with_filter("test.fine")
    fake_pat = "github_pat_11ABCDEFG0xyz1234567890_abcdefghijklmnopqrstuvwxyz1234567890"
    with caplog.at_level(logging.INFO, logger="test.fine"):
        logger.info("auth with %s", fake_pat)

    for record in caplog.records:
        message = record.getMessage()
        assert fake_pat not in message
        assert "<REDACTED_PAT>" in message


def test_bearer_token_redacted(caplog: pytest.LogCaptureFixture) -> None:
    """A Bearer token string is redacted."""
    logger = _logger_with_filter("test.bearer")
    token = "Bearer " + "a" * 40
    with caplog.at_level(logging.INFO, logger="test.bearer"):
        logger.info("header %s", token)

    for record in caplog.records:
        message = record.getMessage()
        assert "a" * 40 not in message
        assert "<REDACTED>" in message


def test_pat_in_extra_redacted(caplog: pytest.LogCaptureFixture) -> None:
    """A PAT passed via extra={...} is also scrubbed."""
    logger = _logger_with_filter("test.extra")
    fake_pat = "ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD"
    with caplog.at_level(logging.INFO, logger="test.extra"):
        logger.info("auth attempt", extra={"token": fake_pat, "repo": "x/y"})

    for record in caplog.records:
        if hasattr(record, "token"):
            assert fake_pat not in record.token
            assert "<REDACTED_PAT>" in record.token
        if hasattr(record, "repo"):
            assert record.repo == "x/y"


def test_non_secret_strings_unchanged(caplog: pytest.LogCaptureFixture) -> None:
    """Normal strings pass through unchanged."""
    logger = logging.getLogger("test.plain.nosecret")
    with caplog.at_level(logging.INFO, logger="test.plain.nosecret"):
        logger.info("scanned axios v1.0.0, found 178 findings")

    assert caplog.records
    assert "axios v1.0.0, found 178 findings" in caplog.records[0].getMessage()


def test_configure_logging_applies_secret_filter() -> None:
    """Root arguss handler has SecretFilter installed."""
    import arguss.logging_config as logging_config

    was_configured = logging_config._CONFIGURED
    root = logging.getLogger("arguss")
    prior_handlers = list(root.handlers)
    prior_propagate = root.propagate
    try:
        logging_config._CONFIGURED = False
        logging_config.configure_logging("INFO")
        assert root.handlers
        assert any(isinstance(f, SecretFilter) for h in root.handlers for f in h.filters)
    finally:
        root.handlers.clear()
        root.handlers.extend(prior_handlers)
        root.propagate = prior_propagate
        logging_config._CONFIGURED = was_configured
