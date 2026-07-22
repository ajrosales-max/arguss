"""Installation liveness check on authorize GET / Begin (no webhook)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import _SESSION_COOKIE_NAME
from arguss.settings import settings
from arguss.web.github_app_auth import GitHubAppAuthError
from arguss.web.github_install import SESSION_INSTALLATION_ID_KEY
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict
from tests.web.session_helpers import (
    TEST_SESSION_SECRET,
    make_session_client,
    seed_github_installation,
)

_HASH = "liveness-check-hash"
_TEST_INSTALLATION_ID = 424242


@pytest.fixture
def wizard_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    db = tmp_path / "wizard.db"
    monkeypatch.setattr(settings, "db_path", db)
    return db


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    return make_session_client(monkeypatch)


def _mode_a_scan() -> dict[str, Any]:
    return _cached_scan_dict(
        entries=[_cached_entry(package="left-pad", tier="auto_merge")],
        mode="A",
    )


def _through_select(client: TestClient, scan: dict[str, Any]) -> None:
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        client.post(f"/assessment/{_HASH}/plan", follow_redirects=False)
        client.post(
            "/select",
            data={"selected_candidate_ids": ["cand-left-pad-001"]},
            follow_redirects=False,
        )


def _set_cookie_headers(response: Any) -> list[str]:
    return [v for k, v in response.headers.multi_items() if k.lower() == "set-cookie"]


def _session_cleared_via_set_cookie(response: Any) -> bool:
    """True when middleware expires or rewrites the session without an install id."""
    import json
    from base64 import b64decode
    from urllib.parse import unquote

    from itsdangerous import BadSignature, TimestampSigner

    for header in _set_cookie_headers(response):
        if _SESSION_COOKIE_NAME not in header:
            continue
        if "expires=Thu, 01 Jan 1970" in header or f"{_SESSION_COOKIE_NAME}=null" in header:
            return True
        # Updated cookie: decode payload and ensure installation id is absent.
        # Format: name=value; attrs…
        try:
            pair = header.split(";", 1)[0]
            raw = unquote(pair.split("=", 1)[1])
        except (IndexError, ValueError):
            continue
        if raw in ("", "null"):
            return True
        try:
            unsigned = TimestampSigner(str(TEST_SESSION_SECRET)).unsign(
                raw.encode("utf-8") if isinstance(raw, str) else raw,
                max_age=86400 * 14,
            )
        except BadSignature:
            continue
        payload = json.loads(b64decode(unsigned))
        if SESSION_INSTALLATION_ID_KEY not in payload:
            return True
    return False


def test_authorize_get_gone_installation_renders_reconnect_and_clears_session(
    client: TestClient,
    wizard_db: Path,
) -> None:
    scan = _mode_a_scan()
    _through_select(client, scan)
    seed_github_installation(client, _TEST_INSTALLATION_ID)

    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(dashboard_mod, "installation_exists", return_value=False),
    ):
        response = client.get("/authorize")

    assert response.status_code == status.HTTP_200_OK
    assert "arguss-bot is connected" not in response.text
    assert 'href="/github/install?next=/authorize"' in response.text
    assert "Connect arguss-bot" in response.text
    # Middleware expires the cookie; TestClient may keep a stale jar entry, so
    # assert the Set-Cookie clear and drop the jar cookie like a real browser.
    assert _session_cleared_via_set_cookie(response)
    client.cookies.delete(_SESSION_COOKIE_NAME)

    # Cleared session stays disconnected even if a later check would say live.
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(dashboard_mod, "installation_exists") as exists,
    ):
        again = client.get("/authorize")
    exists.assert_not_called()
    assert "arguss-bot is connected" not in again.text


def test_authorize_get_live_installation_renders_connected(
    client: TestClient,
    wizard_db: Path,
) -> None:
    scan = _mode_a_scan()
    _through_select(client, scan)
    seed_github_installation(client, _TEST_INSTALLATION_ID)

    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(dashboard_mod, "installation_exists", return_value=True),
    ):
        response = client.get("/authorize")

    assert response.status_code == status.HTTP_200_OK
    assert "arguss-bot is connected" in response.text
    assert f"#{_TEST_INSTALLATION_ID}" in response.text
    assert not _session_cleared_via_set_cookie(response)


def test_authorize_get_transient_error_keeps_connected_session(
    client: TestClient,
    wizard_db: Path,
) -> None:
    scan = _mode_a_scan()
    _through_select(client, scan)
    seed_github_installation(client, _TEST_INSTALLATION_ID)

    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(
            dashboard_mod,
            "installation_exists",
            side_effect=GitHubAppAuthError("HTTP 503"),
        ),
    ):
        response = client.get("/authorize")

    assert response.status_code == status.HTTP_200_OK
    assert "arguss-bot is connected" in response.text
    assert not _session_cleared_via_set_cookie(response)


def test_begin_gone_installation_redirects_without_starting_run(
    client: TestClient,
    wizard_db: Path,
) -> None:
    scan = _mode_a_scan()
    _through_select(client, scan)
    seed_github_installation(client, _TEST_INSTALLATION_ID)

    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(dashboard_mod, "installation_exists", return_value=False),
        mock.patch.object(dashboard_mod, "create_action_record") as create_record,
        mock.patch.object(dashboard_mod, "run_scan_background") as bg,
    ):
        response = client.post("/authorize", follow_redirects=False)

    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"] == "/authorize"
    create_record.assert_not_called()
    bg.assert_not_called()
    # Server rewrote/cleared the install id in Set-Cookie (TestClient may not
    # apply 303 cookies; decode the header rather than the jar).
    assert _session_cleared_via_set_cookie(response)


def test_begin_live_installation_proceeds(
    client: TestClient,
    wizard_db: Path,
) -> None:
    scan = _mode_a_scan()
    _through_select(client, scan)
    seed_github_installation(client, _TEST_INSTALLATION_ID)

    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(dashboard_mod, "installation_exists", return_value=True),
        mock.patch.object(
            dashboard_mod,
            "register_scan_stream",
            new=mock.AsyncMock(return_value=("sid-live", mock.MagicMock())),
        ),
        mock.patch.object(dashboard_mod, "run_scan_background", new=mock.AsyncMock()),
        mock.patch.object(dashboard_mod, "attach_background_task", new=mock.AsyncMock()),
    ):
        response = client.post("/authorize", follow_redirects=False)

    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"].startswith("/process?scan_id=")


def test_begin_transient_liveness_error_still_proceeds(
    client: TestClient,
    wizard_db: Path,
) -> None:
    scan = _mode_a_scan()
    _through_select(client, scan)
    seed_github_installation(client, _TEST_INSTALLATION_ID)

    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(
            dashboard_mod,
            "installation_exists",
            side_effect=GitHubAppAuthError("HTTP 503"),
        ),
        mock.patch.object(
            dashboard_mod,
            "register_scan_stream",
            new=mock.AsyncMock(return_value=("sid-blip", mock.MagicMock())),
        ),
        mock.patch.object(dashboard_mod, "run_scan_background", new=mock.AsyncMock()),
        mock.patch.object(dashboard_mod, "attach_background_task", new=mock.AsyncMock()),
    ):
        response = client.post("/authorize", follow_redirects=False)

    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"].startswith("/process?scan_id=")


_RECONNECT_NOTE = "Your previous arguss-bot connection is no longer valid"


def test_authorize_reconnect_flag_renders_note_and_connect_cta(
    client: TestClient,
    wizard_db: Path,
) -> None:
    scan = _mode_a_scan()
    _through_select(client, scan)
    seed_github_installation(client, _TEST_INSTALLATION_ID)

    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(dashboard_mod, "installation_exists", return_value=False),
    ):
        response = client.get("/authorize")

    assert response.status_code == status.HTTP_200_OK
    assert _RECONNECT_NOTE in response.text
    assert "authorize-reconnect-note" in response.text
    assert 'href="/github/install?next=/authorize"' in response.text
    assert "arguss-bot is connected" not in response.text
    # Distinct from prior-run failure banner.
    assert "Previous attempt failed" not in response.text


def test_authorize_normal_not_connected_omits_reconnect_note(
    client: TestClient,
    wizard_db: Path,
) -> None:
    scan = _mode_a_scan()
    _through_select(client, scan)

    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/authorize")

    assert response.status_code == status.HTTP_200_OK
    assert _RECONNECT_NOTE not in response.text
    assert "authorize-reconnect-note" not in response.text
    assert 'href="/github/install?next=/authorize"' in response.text
