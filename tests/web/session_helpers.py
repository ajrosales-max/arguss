"""Helpers for Starlette session cookies in web tests (GitHub App install flow)."""

from __future__ import annotations

import json
from base64 import b64encode
from typing import Any

import pytest
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner

from arguss.api import _SESSION_COOKIE_NAME, create_app
from arguss.settings import Settings, settings
from arguss.web.github_install import SESSION_INSTALLATION_ID_KEY

TEST_SESSION_SECRET = "unit-test-session-secret-not-for-production"


def make_session_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Build a TestClient whose app has SessionMiddleware (SameSite=Lax)."""
    monkeypatch.setattr(settings, "session_secret", TEST_SESSION_SECRET)
    monkeypatch.setattr(Settings, "session_secret", TEST_SESSION_SECRET)
    monkeypatch.setattr(settings, "demo_password", None)
    monkeypatch.setattr(Settings, "demo_password", None)
    monkeypatch.setattr(settings, "enable_scheduler", False)
    monkeypatch.setattr(Settings, "enable_scheduler", False)
    monkeypatch.setattr(settings, "is_production", False)
    monkeypatch.setattr(Settings, "is_production", False)
    return TestClient(create_app())


def seed_github_installation(client: TestClient, installation_id: int) -> None:
    """Bind a verified installation_id into the signed session cookie."""
    payload = b64encode(json.dumps({SESSION_INSTALLATION_ID_KEY: installation_id}).encode("utf-8"))
    signed = TimestampSigner(str(TEST_SESSION_SECRET)).sign(payload)
    value = signed.decode("utf-8") if isinstance(signed, bytes) else signed
    client.cookies.set(_SESSION_COOKIE_NAME, value)


def post_wizard_authorize(client: TestClient, installation_id: int = 12345) -> Any:
    """POST /authorize after seeding the session installation_id (browser enact path)."""
    seed_github_installation(client, installation_id)
    return client.post("/authorize", follow_redirects=False)
