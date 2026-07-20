"""Shared helpers for session-gated wizard route tests."""

from __future__ import annotations

from typing import Any
from unittest import mock

from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.settings import settings
from arguss.web.wizard_session import WIZARD_SESSION_COOKIE


def patch_wizard_db(monkeypatch, tmp_path) -> None:
    db = tmp_path / "wizard-test.db"
    monkeypatch.setattr(settings, "db_path", db)


def _start_wizard_session(
    client: TestClient,
    scan_hash: str,
    scan: dict[str, Any],
    monkeypatch,
    tmp_path,
) -> None:
    """POST plan to create session; TestClient retains session cookie."""
    patch_wizard_db(monkeypatch, tmp_path)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.post(f"/assessment/{scan_hash}/plan", follow_redirects=False)
    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"] == "/select"
    assert WIZARD_SESSION_COOKIE in response.cookies


def _wizard_at_select(
    client: TestClient,
    scan_hash: str,
    scan: dict[str, Any],
    monkeypatch,
    tmp_path,
) -> None:
    _start_wizard_session(client, scan_hash, scan, monkeypatch, tmp_path)


def _wizard_at_authorize(
    client: TestClient,
    scan_hash: str,
    scan: dict[str, Any],
    monkeypatch,
    tmp_path,
    selected_candidate_ids: list[str],
) -> None:
    _start_wizard_session(client, scan_hash, scan, monkeypatch, tmp_path)
    data = [("selected_candidate_ids", cid) for cid in selected_candidate_ids]
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.post("/select", data=data, follow_redirects=False)
    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"] == "/authorize"


def _wizard_at_process(
    client: TestClient,
    scan_hash: str,
    scan: dict[str, Any],
    monkeypatch,
    tmp_path,
    selected_candidate_ids: list[str],
    installation_id: int = 12345,
) -> str:
    """Returns process page URL after authorize redirect."""
    _wizard_at_authorize(client, scan_hash, scan, monkeypatch, tmp_path, selected_candidate_ids)
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(
            dashboard_mod,
            "register_scan_stream",
            new=mock.AsyncMock(return_value=("scan-test-123", mock.MagicMock())),
        ),
        mock.patch.object(dashboard_mod, "run_scan_background", new=mock.AsyncMock()),
        mock.patch.object(dashboard_mod, "attach_background_task", new=mock.AsyncMock()),
    ):
        response = client.post(
            "/authorize", data={"installation_id": installation_id}, follow_redirects=False
        )
    assert response.status_code == status.HTTP_303_SEE_OTHER
    return response.headers["location"]


def wizard_select_page(
    client: TestClient,
    scan_hash: str,
    scan: dict[str, Any],
    monkeypatch,
    tmp_path,
) -> Any:
    """POST plan then GET /select; returns select page response."""
    _start_wizard_session(client, scan_hash, scan, monkeypatch, tmp_path)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/select")
    assert response.status_code == status.HTTP_200_OK
    return response


def wizard_authorize_page(
    client: TestClient,
    scan_hash: str,
    scan: dict[str, Any],
    monkeypatch,
    tmp_path,
    selected_candidate_ids: list[str],
) -> Any:
    """Reach authorize step and GET /authorize HTML."""
    _wizard_at_authorize(client, scan_hash, scan, monkeypatch, tmp_path, selected_candidate_ids)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/authorize")
    assert response.status_code == status.HTTP_200_OK
    return response
