"""Tests for OAuth/session Settings and SessionMiddleware (install-flow Step 2)."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from arguss.api import _SESSION_COOKIE_NAME, create_app
from arguss.settings import Settings, settings, validate_settings


def test_oauth_session_settings_default_to_none_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "github_app_client_id", None)
    monkeypatch.setattr(settings, "github_app_client_secret", None)
    monkeypatch.setattr(settings, "github_app_slug", None)
    monkeypatch.setattr(settings, "session_secret", None)
    monkeypatch.setattr(Settings, "github_app_client_id", None)
    monkeypatch.setattr(Settings, "github_app_client_secret", None)
    monkeypatch.setattr(Settings, "github_app_slug", None)
    monkeypatch.setattr(Settings, "session_secret", None)

    assert settings.github_app_client_id is None
    assert settings.github_app_client_secret is None
    assert settings.github_app_slug is None
    assert settings.session_secret is None
    validate_settings(require_ai=False)


def test_oauth_session_settings_parse_assigned_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Settings fields accept ARGUSS_* values (same eager-optional pattern as App ID)."""
    monkeypatch.setattr(settings, "github_app_client_id", "Iv1.example")
    monkeypatch.setattr(settings, "github_app_client_secret", "secret-value")
    monkeypatch.setattr(settings, "github_app_slug", "arguss")
    monkeypatch.setattr(settings, "session_secret", "session-signing-key")

    assert settings.github_app_client_id == "Iv1.example"
    assert settings.github_app_client_secret == "secret-value"
    assert settings.github_app_slug == "arguss"
    assert settings.session_secret == "session-signing-key"


def test_import_and_create_app_without_session_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "session_secret", None)
    monkeypatch.setattr(Settings, "session_secret", None)
    monkeypatch.setattr(settings, "demo_password", None)
    monkeypatch.setattr(Settings, "demo_password", None)
    monkeypatch.setattr(settings, "enable_scheduler", False)
    monkeypatch.setattr(Settings, "enable_scheduler", False)

    app = create_app()
    middleware_names = [cls.__name__ for cls in _middleware_classes(app)]
    assert "SessionMiddleware" not in middleware_names


def test_session_round_trip_and_samesite_lax(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "unit-test-session-secret-not-for-production"
    monkeypatch.setattr(settings, "session_secret", secret)
    monkeypatch.setattr(Settings, "session_secret", secret)
    monkeypatch.setattr(settings, "demo_password", None)
    monkeypatch.setattr(Settings, "demo_password", None)
    monkeypatch.setattr(settings, "enable_scheduler", False)
    monkeypatch.setattr(Settings, "enable_scheduler", False)
    monkeypatch.setattr(settings, "is_production", False)
    monkeypatch.setattr(Settings, "is_production", False)

    app = create_app()

    @app.get("/_test/session-set")
    async def session_set(request: Request) -> dict[str, str]:
        request.session["probe"] = "round-trip-ok"
        return {"status": "set"}

    @app.get("/_test/session-get")
    async def session_get(request: Request) -> dict[str, Any]:
        return {"probe": request.session.get("probe")}

    client = TestClient(app)
    set_response = client.get("/_test/session-set")
    assert set_response.status_code == 200

    set_cookie = set_response.headers.get("set-cookie", "")
    assert _SESSION_COOKIE_NAME in set_cookie
    assert "samesite=lax" in set_cookie.lower()
    assert "samesite=strict" not in set_cookie.lower()

    get_response = client.get("/_test/session-get")
    assert get_response.status_code == 200
    assert get_response.json() == {"probe": "round-trip-ok"}


def _middleware_classes(app: Any) -> list[type]:
    classes: list[type] = []
    for middleware in app.user_middleware:
        cls = getattr(middleware, "cls", None)
        if cls is not None:
            classes.append(cls)
    return classes
