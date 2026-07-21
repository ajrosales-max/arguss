"""Authorize page layout on first visit vs retry after failure."""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.settings import settings
from arguss.web.action_records import mirror_action_event
from arguss.web.wizard_session import WIZARD_SESSION_COOKIE, load_session
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict
from tests.web.session_helpers import make_session_client, seed_github_installation

_HASH = "authorize-retry-layout-hash"


@pytest.fixture
def wizard_db(monkeypatch: pytest.MonkeyPatch, tmp_path):
    db = tmp_path / "wizard.db"
    monkeypatch.setattr(settings, "db_path", db)
    return db


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    return make_session_client(monkeypatch)


def _mode_a_scan(*entries: dict[str, Any]) -> dict[str, Any]:
    return _cached_scan_dict(entries=list(entries), mode="A")


def _authorize_after_failure_html(client: TestClient, wizard_db) -> str:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        client.post(f"/assessment/{_HASH}/plan", follow_redirects=False)
        client.post(
            "/select",
            data={"selected_candidate_ids": ["cand-left-pad-001"]},
            follow_redirects=False,
        )
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(
            dashboard_mod,
            "register_scan_stream",
            new=mock.AsyncMock(return_value=("sid-retry", mock.MagicMock())),
        ),
        mock.patch.object(dashboard_mod, "run_scan_background", new=mock.AsyncMock()),
        mock.patch.object(dashboard_mod, "attach_background_task", new=mock.AsyncMock()),
    ):
        seed_github_installation(client, 12345)
        client.post("/authorize", follow_redirects=False)
    token = client.cookies.get(WIZARD_SESSION_COOKIE)
    session = load_session(token, wizard_db)
    assert session is not None and session.action_id
    mirror_action_event(
        session.action_id,
        {"type": "scan_failed", "reason": "Invalid or expired PAT"},
        wizard_db,
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/authorize")
    assert response.status_code == status.HTTP_200_OK
    return response.text


def test_authorize_first_visit_not_connected_shows_connect_cta(
    client: TestClient, wizard_db
) -> None:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        client.post(f"/assessment/{_HASH}/plan", follow_redirects=False)
        client.post(
            "/select",
            data={"selected_candidate_ids": ["cand-left-pad-001"]},
            follow_redirects=False,
        )
        response = client.get("/authorize")
    assert response.status_code == status.HTTP_200_OK
    html = response.text
    assert "Connect arguss-bot" in html
    assert 'href="/github/install?next=/authorize"' in html
    assert 'id="wizard-begin-btn"' not in html
    assert 'name="pat"' not in html


def test_authorize_after_failure_shows_banner_and_retry_when_connected(
    client: TestClient, wizard_db
) -> None:
    html = _authorize_after_failure_html(client, wizard_db)
    assert "Previous attempt failed" in html
    assert "select Begin to retry" in html
    assert 'id="wizard-begin-btn"' in html
    assert 'name="pat"' not in html
    assert "Create token on GitHub" not in html
