"""Global pytest fixtures."""

import logging

import pytest

from arguss.settings import settings


@pytest.fixture(autouse=True)
def _disable_demo_auth_by_default(monkeypatch):
    """Disable demo auth for all tests by default.

    The demo auth dependency gates routes when settings.demo_password is set.
    In a developer environment .env may have ARGUSS_DEMO_PASSWORD configured
    for testing the live deploy, which would cause every protected-route
    test to return 401. We disable it globally here.

    Tests that specifically verify auth behavior (test_demo_auth.py) override
    this within their own monkeypatch — the later setattr wins.
    """
    monkeypatch.setattr(settings, "demo_password", None)


@pytest.fixture(autouse=True)
def _isolate_db_path(tmp_path_factory, monkeypatch):
    """Point settings.db_path at a per-test temp DB by default.

    call_claude now writes the durable Anthropic day-counter through
    settings.db_path, so tests that exercise it (with a mocked Anthropic
    client) must never touch the developer's real ./arguss.db. Tests that
    need a specific path monkeypatch db_path themselves — the later setattr
    wins.
    """
    db_dir = tmp_path_factory.mktemp("isolated-db")
    monkeypatch.setattr(settings, "db_path", db_dir / "arguss.db")


@pytest.fixture(autouse=True)
def _reset_scan_rate_limit_state():
    """Fresh in-memory scan-frequency counters per test.

    The limiter is a module-level singleton keyed by client IP; without a
    reset, unrelated endpoint tests (all sharing the TestClient IP) would
    exhaust the hourly scan budget across the suite.
    """
    from arguss.web.scan_rate_limit import reset_scan_rate_limit_state

    reset_scan_rate_limit_state()
    yield
    reset_scan_rate_limit_state()


@pytest.fixture(autouse=True)
def _disable_scheduler_by_default(monkeypatch):
    """Disable the top-1000 sweep scheduler for all tests by default.

    Scheduler tests opt in via ``enable_top_1000_scheduler``.
    """
    monkeypatch.setattr(settings, "enable_scheduler", False)


@pytest.fixture(autouse=True)
def _logging_isolation() -> None:
    """Reset arguss logging so caplog captures WARNING records on the root logger."""
    import arguss.logging_config as logging_config

    root = logging.getLogger("arguss")
    saved_handlers = list(root.handlers)
    saved_propagate = root.propagate
    saved_configured = logging_config._CONFIGURED

    root.handlers.clear()
    root.propagate = True
    logging_config._CONFIGURED = False

    yield

    root.handlers.clear()
    root.handlers.extend(saved_handlers)
    root.propagate = saved_propagate
    logging_config._CONFIGURED = saved_configured


@pytest.fixture
def wizard_db(tmp_path, monkeypatch):
    from arguss.settings import settings

    db = tmp_path / "wizard.sqlite"
    monkeypatch.setattr(settings, "db_path", db)
    return db


@pytest.fixture
def enable_top_1000_scheduler(monkeypatch):
    """Opt-in: allow lifespan startup to create the sweep scheduler."""
    monkeypatch.setattr(settings, "enable_scheduler", True)
