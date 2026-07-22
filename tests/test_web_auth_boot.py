"""Web create_app fails closed when auth is required without a password."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import arguss.api as api_mod
import arguss.settings as settings_mod
from arguss.api import create_app
from arguss.settings import _WEB_AUTH_BOOT_ERROR, Settings, settings


def _patch_auth(
    monkeypatch: pytest.MonkeyPatch,
    *,
    require_auth: bool,
    demo_password: str | None,
) -> None:
    monkeypatch.setattr(settings, "require_auth", require_auth)
    monkeypatch.setattr(settings, "demo_password", demo_password)
    monkeypatch.setattr(Settings, "require_auth", require_auth)
    monkeypatch.setattr(Settings, "demo_password", demo_password)
    monkeypatch.setattr(settings_mod, "settings", settings)
    monkeypatch.setattr(api_mod, "settings", settings)


def test_create_app_fails_when_require_auth_without_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_auth(monkeypatch, require_auth=True, demo_password=None)
    with pytest.raises(SystemExit, match="ARGUSS_REQUIRE_AUTH is enabled") as exc_info:
        create_app()
    assert str(exc_info.value) == _WEB_AUTH_BOOT_ERROR


def test_create_app_boots_when_require_auth_with_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_auth(monkeypatch, require_auth=True, demo_password="secret")
    app = create_app()
    assert TestClient(app).get("/health").status_code == 200


def test_create_app_boots_when_auth_open_without_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_auth(monkeypatch, require_auth=False, demo_password=None)
    app = create_app()
    assert TestClient(app).get("/health").status_code == 200
