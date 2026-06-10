"""Tests for Phase 2 wizard URL restructure and session gating."""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from arguss.settings import settings
from arguss.web.wizard_session import LAST_SCAN_COOKIE, WIZARD_SESSION_COOKIE
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict

_HASH = "wizard-routes-demo"
_HEX_HASH = "a" * 64
_TEST_PAT = "github_pat_test_token_1234567890abcdef"
_UUID = "12345678-1234-1234-1234-123456789012"


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


@pytest.fixture
def wizard_db(monkeypatch: pytest.MonkeyPatch, tmp_path):
    monkeypatch.setattr(settings, "db_path", tmp_path / "wizard.db")


def _mode_a_scan(*entries: dict[str, Any]) -> dict[str, Any]:
    return _cached_scan_dict(
        entries=list(entries) or [_cached_entry(package="left-pad", tier="auto_merge")], mode="A"
    )


def _post_plan(client, scan_hash, scan):
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        return client.post(f"/assessment/{scan_hash}/plan", follow_redirects=False)


def _through_select(client, scan_hash, scan, ids):
    _post_plan(client, scan_hash, scan)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        return client.post("/select", data={"selected_candidate_ids": ids}, follow_redirects=False)


def test_get_assessment_renders_and_sets_last_scan_cookie(client, wizard_db):
    scan = _mode_a_scan()
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.get(f"/assessment/{_HASH}")
    assert r.status_code == 200 and r.cookies[LAST_SCAN_COOKIE] == _HASH


def test_post_assessment_plan_creates_session_and_redirects_to_select(client, wizard_db):
    r = _post_plan(client, _HASH, _mode_a_scan())
    assert (
        r.status_code == 303
        and r.headers["location"] == "/select"
        and WIZARD_SESSION_COOKIE in r.cookies
    )


def test_post_assessment_plan_404_when_scan_not_cached(client, wizard_db):
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=None):
        r = client.post(f"/assessment/{_HASH}/plan")
    assert r.status_code == 404


def test_get_select_with_valid_session_renders(client, wizard_db):
    scan = _mode_a_scan()
    _post_plan(client, _HASH, scan)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.get("/select")
    assert r.status_code == 200 and "candidate-selection" in r.text


def test_post_select_persists_selection_and_redirects_to_authorize(client, wizard_db):
    scan = _mode_a_scan()
    r = _through_select(client, _HASH, scan, ["cand-left-pad-001"])
    assert r.status_code == 303 and r.headers["location"] == "/authorize"


def test_post_select_rejects_invalid_candidate_id(client, wizard_db):
    scan = _mode_a_scan()
    _post_plan(client, _HASH, scan)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.post("/select", data={"selected_candidate_ids": ["bad-id"]})
    assert r.status_code == 400


def test_get_authorize_with_valid_session_renders(client, wizard_db):
    scan = _mode_a_scan()
    _through_select(client, _HASH, scan, ["cand-left-pad-001"])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.get("/authorize")
    assert r.status_code == 200 and "Authorize GitHub access" in r.text


def test_post_authorize_kicks_off_stream_and_redirects_to_process(client, wizard_db):
    scan = _mode_a_scan()
    cap = {}

    async def fake_bg(scan_id, **kw):
        cap.update(kw)

    _through_select(client, _HASH, scan, ["cand-left-pad-001"])
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(
            dashboard_mod,
            "register_scan_stream",
            new=mock.AsyncMock(return_value=("sid", mock.MagicMock())),
        ),
        mock.patch.object(dashboard_mod, "run_scan_background", side_effect=fake_bg),
        mock.patch.object(dashboard_mod, "attach_background_task", new=mock.AsyncMock()),
    ):
        r = client.post("/authorize", data={"pat": _TEST_PAT}, follow_redirects=False)
    assert (
        r.status_code == 303
        and r.headers["location"].startswith("/process?scan_id=")
        and cap.get("selected_candidate_ids") == ["cand-left-pad-001"]
    )


def test_get_process_with_valid_session_renders(client, wizard_db):
    scan = _mode_a_scan()
    _through_select(client, _HASH, scan, ["cand-left-pad-001"])
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(
            dashboard_mod,
            "register_scan_stream",
            new=mock.AsyncMock(return_value=("sid2", mock.MagicMock())),
        ),
        mock.patch.object(dashboard_mod, "run_scan_background", new=mock.AsyncMock()),
        mock.patch.object(dashboard_mod, "attach_background_task", new=mock.AsyncMock()),
    ):
        loc = client.post("/authorize", data={"pat": _TEST_PAT}, follow_redirects=False).headers[
            "location"
        ]
        with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
            r = client.get(loc)
    assert r.status_code == 200 and "sid2" in r.text


def test_get_select_without_session_redirects(client, wizard_db):
    r = client.get("/select", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/scan?wizard_note=expired"


def test_get_authorize_with_wrong_step_redirects(client, wizard_db):
    scan = _mode_a_scan()
    _post_plan(client, _HASH, scan)
    client.cookies.set(LAST_SCAN_COOKIE, _HASH)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.get("/authorize", follow_redirects=False)
    assert (
        r.status_code == 303 and r.headers["location"] == f"/assessment/{_HASH}?wizard_note=expired"
    )


def test_get_process_without_session_uses_last_scan_recovery(client, wizard_db):
    client.cookies.set(LAST_SCAN_COOKIE, _HASH)
    r = client.get("/process", follow_redirects=False)
    assert (
        r.status_code == 303 and r.headers["location"] == f"/assessment/{_HASH}?wizard_note=expired"
    )


def test_old_results_scan_hash_redirects_to_assessment_301(client):
    r = client.get(f"/results/{_HEX_HASH}", follow_redirects=False)
    assert r.status_code == 301 and r.headers["location"] == f"/assessment/{_HEX_HASH}"


def test_old_results_uuid_returns_404_until_phase_3(client):
    assert client.get(f"/results/{_UUID}").status_code == 404


def test_old_results_unknown_format_returns_404(client):
    assert client.get("/results/deadbeef").status_code == 404


def test_old_results_hash_plan_redirects_303_to_scan(client):
    r = client.get(f"/results/{_HASH}/plan", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/scan?wizard_note=url_moved"


def test_old_results_hash_authorize_redirects_303_to_scan(client):
    r = client.get(f"/results/{_HASH}/authorize", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/scan?wizard_note=url_moved"


def test_old_results_hash_process_redirects_303_to_scan(client):
    r = client.get(f"/results/{_HASH}/process", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/scan?wizard_note=url_moved"


def test_wizard_note_expired_renders_banner_on_assessment(client, wizard_db):
    scan = _mode_a_scan()
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.get(f"/assessment/{_HASH}?wizard_note=expired")
    assert r.status_code == 200 and "Session expired" in r.text


def test_wizard_note_url_moved_renders_banner_on_scan(client):
    r = client.get("/scan?wizard_note=url_moved")
    assert r.status_code == 200 and "Remediation URLs have moved" in r.text
