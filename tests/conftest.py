"""Global pytest fixtures."""

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
