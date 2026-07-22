"""Tests for GitHub App install + OAuth callback routes (outside demo auth)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest import mock
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from arguss.api import create_app
from arguss.settings import Settings, settings
from arguss.web import github_install
from arguss.web.github_app_auth import GitHubAppAuthError
from arguss.web.github_install import (
    DEFAULT_RESUME_REDIRECT,
    SESSION_INSTALLATION_ID_KEY,
    SESSION_OAUTH_STATE_KEY,
    SESSION_RETURN_PATH_KEY,
    clear_session_installation_id,
)

_TEST_SESSION_SECRET = "unit-test-session-secret-not-for-production"
_TEST_SLUG = "arguss-test-app"
_TEST_INSTALLATION_ID = 424242


@pytest.fixture
def install_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setattr(settings, "session_secret", _TEST_SESSION_SECRET)
    monkeypatch.setattr(Settings, "session_secret", _TEST_SESSION_SECRET)
    monkeypatch.setattr(settings, "github_app_slug", _TEST_SLUG)
    monkeypatch.setattr(Settings, "github_app_slug", _TEST_SLUG)
    monkeypatch.setattr(settings, "demo_password", "demo-pass")
    monkeypatch.setattr(Settings, "demo_password", "demo-pass")
    monkeypatch.setattr(settings, "enable_scheduler", False)
    monkeypatch.setattr(Settings, "enable_scheduler", False)
    monkeypatch.setattr(settings, "is_production", False)
    monkeypatch.setattr(Settings, "is_production", False)

    app = create_app()

    @app.get("/_test/session-dump")
    async def _session_dump(request: Request) -> dict[str, Any]:
        return {
            "installation_id": request.session.get(SESSION_INSTALLATION_ID_KEY),
            "state": request.session.get(SESSION_OAUTH_STATE_KEY),
            "return_path": request.session.get(SESSION_RETURN_PATH_KEY),
            "keys": sorted(request.session.keys()),
            "raw": dict(request.session),
        }

    @app.get("/_test/session-set")
    async def _session_set(request: Request, key: str, value: str) -> dict[str, Any]:
        request.session[key] = value
        return {"ok": True}

    with TestClient(app) as client:
        yield client


def _start_install(
    client: TestClient,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> str:
    response = client.get("/github/install", params=params, headers=headers, follow_redirects=False)
    assert response.status_code == 302
    location = response.headers["location"]
    query = parse_qs(urlparse(location).query)
    return query["state"][0]


def _callback_success(client: TestClient, state: str) -> Any:
    """Drive a mocked happy-path callback and return the raw response."""
    with (
        mock.patch.object(
            github_install,
            "exchange_oauth_code_for_user_token",
            return_value="ghu_user",
        ),
        mock.patch.object(
            github_install,
            "user_can_access_installation",
            return_value=True,
        ),
    ):
        return client.get(
            "/github/callback",
            params={
                "code": "oauth-code",
                "installation_id": str(_TEST_INSTALLATION_ID),
                "setup_action": "install",
                "state": state,
            },
            follow_redirects=False,
        )


def _session(client: TestClient) -> dict[str, Any]:
    response = client.get("/_test/session-dump")
    assert response.status_code == 200
    return response.json()


def test_install_sets_state_and_redirects_to_github(install_client: TestClient) -> None:
    response = install_client.get("/github/install", follow_redirects=False)
    assert response.status_code == 302
    location = response.headers["location"]
    parsed = urlparse(location)
    assert parsed.scheme == "https"
    assert parsed.netloc == "github.com"
    assert parsed.path == f"/apps/{_TEST_SLUG}/installations/new"
    state = parse_qs(parsed.query)["state"][0]
    assert len(state) >= 16
    assert _session(install_client)["state"] == state


def test_callback_happy_path_stores_installation_id(
    install_client: TestClient,
) -> None:
    state = _start_install(install_client)
    user_token = "ghu_transient_must_not_persist"

    with (
        mock.patch.object(
            github_install,
            "exchange_oauth_code_for_user_token",
            return_value=user_token,
        ) as exchange,
        mock.patch.object(
            github_install,
            "user_can_access_installation",
            return_value=True,
        ) as ownership,
    ):
        response = install_client.get(
            "/github/callback",
            params={
                "code": "oauth-code",
                "installation_id": str(_TEST_INSTALLATION_ID),
                "setup_action": "install",
                "state": state,
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert response.headers["location"] == DEFAULT_RESUME_REDIRECT
    exchange.assert_called_once_with("oauth-code")
    ownership.assert_called_once_with(user_token, _TEST_INSTALLATION_ID)

    body = _session(install_client)
    assert body["installation_id"] == _TEST_INSTALLATION_ID
    assert isinstance(body["installation_id"], int)
    assert body["state"] is None
    assert user_token not in str(body)
    assert "ghu_" not in str(body)
    assert "refresh_token" not in str(body).lower()


def test_callback_rejects_state_mismatch(install_client: TestClient) -> None:
    _start_install(install_client)
    with mock.patch.object(github_install, "exchange_oauth_code_for_user_token") as exchange:
        response = install_client.get(
            "/github/callback",
            params={
                "code": "oauth-code",
                "installation_id": str(_TEST_INSTALLATION_ID),
                "state": "attacker-forged-state",
            },
            follow_redirects=False,
        )
    assert response.status_code == 400
    exchange.assert_not_called()
    assert _session(install_client)["installation_id"] is None
    # Nonce preserved on mismatch so a legitimate callback can still succeed.
    assert _session(install_client)["state"] is not None


def test_callback_rejects_ownership_failure(install_client: TestClient) -> None:
    state = _start_install(install_client)
    with (
        mock.patch.object(
            github_install,
            "exchange_oauth_code_for_user_token",
            return_value="ghu_user",
        ),
        mock.patch.object(
            github_install,
            "user_can_access_installation",
            return_value=False,
        ),
    ):
        response = install_client.get(
            "/github/callback",
            params={
                "code": "oauth-code",
                "installation_id": str(_TEST_INSTALLATION_ID),
                "state": state,
            },
            follow_redirects=False,
        )
    assert response.status_code == 403
    assert _session(install_client)["installation_id"] is None


def test_callback_rejects_failed_code_exchange(install_client: TestClient) -> None:
    state = _start_install(install_client)
    with (
        mock.patch.object(
            github_install,
            "exchange_oauth_code_for_user_token",
            side_effect=GitHubAppAuthError("bad code"),
        ),
        mock.patch.object(
            github_install,
            "user_can_access_installation",
        ) as ownership,
    ):
        response = install_client.get(
            "/github/callback",
            params={
                "code": "bad",
                "installation_id": str(_TEST_INSTALLATION_ID),
                "state": state,
            },
            follow_redirects=False,
        )
    assert response.status_code == 400
    ownership.assert_not_called()
    assert _session(install_client)["installation_id"] is None


def test_callback_rejects_non_numeric_installation_id(install_client: TestClient) -> None:
    state = _start_install(install_client)
    with mock.patch.object(
        github_install,
        "exchange_oauth_code_for_user_token",
    ) as exchange:
        response = install_client.get(
            "/github/callback",
            params={
                "code": "oauth-code",
                "installation_id": "not-a-number",
                "state": state,
            },
            follow_redirects=False,
        )
    assert response.status_code == 400
    exchange.assert_not_called()
    assert _session(install_client)["installation_id"] is None


def test_used_state_nonce_cannot_be_replayed(install_client: TestClient) -> None:
    state = _start_install(install_client)
    with (
        mock.patch.object(
            github_install,
            "exchange_oauth_code_for_user_token",
            return_value="ghu_user",
        ),
        mock.patch.object(
            github_install,
            "user_can_access_installation",
            return_value=True,
        ),
    ):
        first = install_client.get(
            "/github/callback",
            params={
                "code": "oauth-code",
                "installation_id": str(_TEST_INSTALLATION_ID),
                "state": state,
            },
            follow_redirects=False,
        )
    assert first.status_code == 302

    with mock.patch.object(
        github_install,
        "exchange_oauth_code_for_user_token",
        return_value="ghu_replay",
    ) as exchange:
        second = install_client.get(
            "/github/callback",
            params={
                "code": "oauth-code-2",
                "installation_id": "999999",
                "state": state,
            },
            follow_redirects=False,
        )
    assert second.status_code == 400
    exchange.assert_not_called()
    # Original verified installation remains; replay must not overwrite.
    assert _session(install_client)["installation_id"] == _TEST_INSTALLATION_ID


def test_github_routes_reachable_without_demo_basic_auth(
    install_client: TestClient,
) -> None:
    protected = install_client.get("/", follow_redirects=False)
    assert protected.status_code == 401

    install = install_client.get("/github/install", follow_redirects=False)
    assert install.status_code == 302

    callback = install_client.get("/github/callback", follow_redirects=False)
    assert callback.status_code == 400


def test_install_stashes_internal_return_path_and_callback_resumes_there(
    install_client: TestClient,
) -> None:
    state = _start_install(install_client, params={"next": "/authorize"})
    assert _session(install_client)["return_path"] == "/authorize"

    response = _callback_success(install_client, state)
    assert response.status_code == 302
    assert response.headers["location"] == "/authorize"


def test_install_derives_return_path_from_same_host_referer(
    install_client: TestClient,
) -> None:
    state = _start_install(
        install_client,
        headers={"referer": "http://testserver/authorize?step=3"},
    )
    assert _session(install_client)["return_path"] == "/authorize?step=3"

    response = _callback_success(install_client, state)
    assert response.headers["location"] == "/authorize?step=3"


def test_install_ignores_cross_host_referer(install_client: TestClient) -> None:
    _start_install(install_client, headers={"referer": "https://evil.com/authorize"})
    assert _session(install_client)["return_path"] is None


def test_callback_without_stashed_path_falls_back_to_default(
    install_client: TestClient,
) -> None:
    state = _start_install(install_client)
    assert _session(install_client)["return_path"] is None

    response = _callback_success(install_client, state)
    assert response.status_code == 302
    assert response.headers["location"] == DEFAULT_RESUME_REDIRECT


@pytest.mark.parametrize(
    "evil_next",
    [
        "https://evil.com/phish",
        "//evil.com/phish",
        "javascript:alert(1)",
        "http:///evil.com",
        "/\\evil.com",
    ],
)
def test_install_rejects_external_return_path(install_client: TestClient, evil_next: str) -> None:
    state = _start_install(install_client, params={"next": evil_next})
    assert _session(install_client)["return_path"] is None

    response = _callback_success(install_client, state)
    assert response.headers["location"] == DEFAULT_RESUME_REDIRECT


def test_callback_revalidates_poisoned_session_return_path(
    install_client: TestClient,
) -> None:
    """Even a value planted directly in the session must not redirect off-site."""
    state = _start_install(install_client)
    install_client.get(
        "/_test/session-set",
        params={"key": SESSION_RETURN_PATH_KEY, "value": "https://evil.com/phish"},
    )
    assert _session(install_client)["return_path"] == "https://evil.com/phish"

    response = _callback_success(install_client, state)
    assert response.status_code == 302
    assert response.headers["location"] == DEFAULT_RESUME_REDIRECT
    assert _session(install_client)["return_path"] is None


def test_stashed_return_path_is_single_use(install_client: TestClient) -> None:
    state = _start_install(install_client, params={"next": "/authorize"})
    first = _callback_success(install_client, state)
    assert first.headers["location"] == "/authorize"
    assert _session(install_client)["return_path"] is None

    # A fresh round-trip without a return path must not reuse the old target.
    second_state = _start_install(install_client)
    second = _callback_success(install_client, second_state)
    assert second.headers["location"] == DEFAULT_RESUME_REDIRECT


def test_install_without_return_path_clears_stale_stash(
    install_client: TestClient,
) -> None:
    _start_install(install_client, params={"next": "/authorize"})
    assert _session(install_client)["return_path"] == "/authorize"

    _start_install(install_client)
    assert _session(install_client)["return_path"] is None


def test_callback_rejects_when_session_middleware_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "session_secret", None)
    monkeypatch.setattr(Settings, "session_secret", None)
    monkeypatch.setattr(settings, "github_app_slug", _TEST_SLUG)
    monkeypatch.setattr(Settings, "github_app_slug", _TEST_SLUG)
    monkeypatch.setattr(settings, "demo_password", None)
    monkeypatch.setattr(Settings, "demo_password", None)
    monkeypatch.setattr(settings, "enable_scheduler", False)
    monkeypatch.setattr(Settings, "enable_scheduler", False)

    client = TestClient(create_app())
    response = client.get("/github/install", follow_redirects=False)
    assert response.status_code == 503
    assert "SESSION_SECRET" in response.json()["detail"]


def test_clear_session_installation_id_removes_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """clear_session_installation_id pops the session key and drops the mint cache."""
    from datetime import UTC, datetime

    from arguss.web import github_app_auth
    from arguss.web.github_app_auth import InstallationAccessToken, clear_installation_token_cache

    request = mock.MagicMock(spec=Request)
    request.session = {SESSION_INSTALLATION_ID_KEY: _TEST_INSTALLATION_ID}

    clear_installation_token_cache()
    try:
        github_app_auth._token_cache[_TEST_INSTALLATION_ID] = InstallationAccessToken(
            token="ghs_stale",
            expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        )
        previous = clear_session_installation_id(request)
        assert previous == _TEST_INSTALLATION_ID
        assert SESSION_INSTALLATION_ID_KEY not in request.session
        assert _TEST_INSTALLATION_ID not in github_app_auth._token_cache
    finally:
        clear_installation_token_cache()

    # Idempotent when already absent.
    assert clear_session_installation_id(request) is None
