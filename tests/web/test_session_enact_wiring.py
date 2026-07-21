"""Browser enact and JSON API both derive installation_id from the verified session."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
import arguss.web.routes as routes_mod
from arguss.settings import settings
from arguss.web.action_runs import create_action_run
from arguss.web.wizard_session import WIZARD_SESSION_COOKIE, load_session
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict
from tests.web.session_helpers import make_session_client, seed_github_installation

_HASH = "step5-session-enact-hash"
_TEST_INSTALLATION_ID = 424242
_EXPRESS_URL = "https://github.com/expressjs/express"


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


def test_browser_enact_with_session_installation_id_threads_to_create_action_run(
    client: TestClient,
    wizard_db: Path,
) -> None:
    """Session installation_id reaches run_scan_background and create_action_run."""
    scan = _mode_a_scan()
    _through_select(client, scan)
    bg_kw: dict[str, Any] = {}

    async def fake_bg(scan_id: str, **kwargs: Any) -> None:
        bg_kw.update(kwargs)
        # Same create_action_run call shape as mode_c_workflow (PR 2).
        create_action_run(
            scan_hash=_HASH,
            mode="C",
            db_path=wizard_db,
            scan_ref="HEAD",
            installation_id=str(kwargs["installation_id"]),
        )

    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(
            dashboard_mod,
            "register_scan_stream",
            new=mock.AsyncMock(return_value=("sid-step5", mock.MagicMock())),
        ),
        mock.patch.object(dashboard_mod, "run_scan_background", side_effect=fake_bg),
        mock.patch.object(dashboard_mod, "attach_background_task", new=mock.AsyncMock()),
    ):
        seed_github_installation(client, _TEST_INSTALLATION_ID)
        response = client.post("/authorize", follow_redirects=False)

    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"].startswith("/process?scan_id=")
    assert bg_kw.get("installation_id") == _TEST_INSTALLATION_ID

    # Persisted run row carries the session-derived id (not null).
    from arguss.core.cache import get_connection, init_db

    conn = get_connection(wizard_db)
    init_db(conn)
    conn.close()
    # create_action_run in fake_bg already wrote; find by scan_hash.
    conn = get_connection(wizard_db)
    row = conn.execute(
        "SELECT installation_id FROM action_run WHERE scan_hash = ?",
        (_HASH,),
    ).fetchone()
    conn.close()
    assert row is not None
    assert row[0] == str(_TEST_INSTALLATION_ID)


def test_browser_enact_without_session_installation_id_redirects_to_install(
    client: TestClient,
    wizard_db: Path,
) -> None:
    """Missing session id → 303 to /github/install; no run created."""
    scan = _mode_a_scan()
    _through_select(client, scan)
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(dashboard_mod, "run_scan_background") as bg,
        mock.patch.object(dashboard_mod, "create_action_record") as create_record,
    ):
        response = client.post("/authorize", follow_redirects=False)

    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"] == "/github/install"
    bg.assert_not_called()
    create_record.assert_not_called()
    token = client.cookies.get(WIZARD_SESSION_COOKIE)
    session = load_session(token, wizard_db)
    assert session is not None
    assert not session.action_id


def test_json_api_requires_session_and_ignores_body_installation_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The JSON endpoint uses the verified session id; a body id is ignored."""
    client = make_session_client(monkeypatch)
    seed_github_installation(client, _TEST_INSTALLATION_ID)
    stub_result = mock.MagicMock()
    stub_result.payload = {
        "scan_meta": {"repo_display": "expressjs/express", "ref": "HEAD", "mode": "C"},
        "entries": [],
    }
    stub_result.scan_hash = "api-hash"
    stub_result.action_run_id = None
    stub_result.report = mock.MagicMock()
    stub_result.actions = []

    with mock.patch.object(
        routes_mod,
        "execute_scan_with_action",
        new=mock.AsyncMock(return_value=stub_result),
    ) as execute:
        response = client.post(
            "/scan/with-action",
            json={"url": _EXPRESS_URL, "installation_id": 999999},
        )

    assert response.status_code == status.HTTP_200_OK
    execute.assert_called_once()
    # Session id wins; the untrusted body value never reaches token minting.
    assert execute.call_args.kwargs["installation_id"] == _TEST_INSTALLATION_ID
