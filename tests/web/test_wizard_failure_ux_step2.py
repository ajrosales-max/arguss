"""Step 2: outcome-driven wizard session lifecycle and authorize guards."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from arguss.core.cache import get_connection
from arguss.settings import settings
from arguss.web.action_records import create_action_record, mirror_action_event
from arguss.web.wizard_session import (
    LAST_SCAN_COOKIE,
    STEP_AUTHORIZE_FAILED,
    STEP_AUTHORIZED,
    STEP_COMPLETED,
    WIZARD_SESSION_COOKIE,
    create_session,
    find_session_by_action_id,
    load_session,
    set_action_id,
    update_step,
)
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict

_HASH = "wizard-failure-step2-hash"
_TEST_PAT = "github_pat_test_token_1234567890abcdef"


@pytest.fixture
def wizard_db(monkeypatch: pytest.MonkeyPatch, tmp_path):
    db = tmp_path / "wizard.db"
    monkeypatch.setattr(settings, "db_path", db)
    return db


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def _mode_a_scan(*entries: dict[str, Any]) -> dict[str, Any]:
    return _cached_scan_dict(entries=list(entries), mode="A")


def _through_authorize(client: TestClient, wizard_db, scan) -> str:
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
            new=mock.AsyncMock(return_value=("scan-step2", mock.MagicMock())),
        ),
        mock.patch.object(dashboard_mod, "run_scan_background", new=mock.AsyncMock()),
        mock.patch.object(dashboard_mod, "attach_background_task", new=mock.AsyncMock()),
    ):
        start = client.post("/authorize", data={"pat": _TEST_PAT}, follow_redirects=False)
    return start.headers["location"]


def test_process_page_load_does_not_transition_to_completed(client: TestClient, wizard_db) -> None:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    loc = _through_authorize(client, wizard_db, scan)
    token = client.cookies.get(WIZARD_SESSION_COOKIE)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.get(loc)
    assert r.status_code == status.HTTP_200_OK
    session = load_session(token, wizard_db)
    assert session is not None
    assert session.current_step == STEP_AUTHORIZED


def test_mirror_scan_complete_transitions_session_to_completed(wizard_db) -> None:
    session = create_session(_HASH, wizard_db)
    record = create_action_record(_HASH, "o/r", ["c1"], wizard_db)
    set_action_id(session.token, record.action_id, wizard_db)
    update_step(session.token, STEP_AUTHORIZED, wizard_db)
    mirror_action_event(
        record.action_id,
        {"type": "scan_complete", "total": 1, "succeeded": 1, "failed": 0, "skipped": 0},
        wizard_db,
    )
    loaded = load_session(session.token, wizard_db)
    assert loaded is not None
    assert loaded.current_step == STEP_COMPLETED


def test_mirror_scan_failed_transitions_session_to_authorize_failed(wizard_db) -> None:
    session = create_session(_HASH, wizard_db)
    record = create_action_record(_HASH, "o/r", ["c1"], wizard_db)
    set_action_id(session.token, record.action_id, wizard_db)
    update_step(session.token, STEP_AUTHORIZED, wizard_db)
    mirror_action_event(
        record.action_id,
        {"type": "scan_failed", "reason": "Invalid or expired PAT"},
        wizard_db,
    )
    loaded = load_session(session.token, wizard_db)
    assert loaded is not None
    assert loaded.current_step == STEP_AUTHORIZE_FAILED


def test_authorize_after_failure_shows_notice_not_expired(client: TestClient, wizard_db) -> None:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    _through_authorize(client, wizard_db, scan)
    token = client.cookies.get(WIZARD_SESSION_COOKIE)
    session = load_session(token, wizard_db)
    assert session is not None and session.action_id
    mirror_action_event(
        session.action_id,
        {"type": "scan_failed", "reason": "Invalid or expired PAT"},
        wizard_db,
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.get("/authorize")
    assert r.status_code == status.HTTP_200_OK
    assert "Invalid or expired PAT" in r.text
    assert "Retry with a different token" in r.text
    assert "timed out" not in r.text.lower()
    assert "Session expired" not in r.text


def test_genuine_ttl_expiry_still_shows_expired_note(client: TestClient, wizard_db) -> None:
    session = create_session(_HASH, wizard_db)
    update_step(session.token, STEP_AUTHORIZE_FAILED, wizard_db)
    conn = get_connection(wizard_db)
    past = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
    conn.execute(
        "UPDATE wizard_sessions SET expires_at = ? WHERE token = ?",
        (past, session.token),
    )
    conn.commit()
    conn.close()
    scan = _mode_a_scan()
    client.cookies.set(WIZARD_SESSION_COOKIE, session.token)
    client.cookies.set(LAST_SCAN_COOKIE, _HASH)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.get("/authorize", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == f"/assessment/{_HASH}?wizard_note=expired"


def test_authorized_with_pending_action_redirects_to_process_in_progress(
    client: TestClient, wizard_db
) -> None:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    _through_authorize(client, wizard_db, scan)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.get("/authorize", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/process?wizard_note=action_in_progress"


def test_post_authorize_rejects_in_flight_action(client: TestClient, wizard_db) -> None:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    _through_authorize(client, wizard_db, scan)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.post("/authorize", data={"pat": _TEST_PAT}, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/process?wizard_note=action_in_progress"


def test_completed_session_authorize_redirects_to_results(client: TestClient, wizard_db) -> None:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    _through_authorize(client, wizard_db, scan)
    token = client.cookies.get(WIZARD_SESSION_COOKIE)
    session = load_session(token, wizard_db)
    assert session and session.action_id
    mirror_action_event(
        session.action_id,
        {"type": "scan_complete", "total": 1, "succeeded": 1, "failed": 0, "skipped": 0},
        wizard_db,
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.get("/authorize", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == f"/results/{session.action_id}?wizard_note=already_completed"


def test_missing_action_record_degrades_to_expired(client: TestClient, wizard_db) -> None:
    session = create_session(_HASH, wizard_db)
    from arguss.web.wizard_session import set_selection

    set_selection(session.token, ["cand-left-pad-001"], ["cand-left-pad-001"], wizard_db)
    update_step(session.token, STEP_AUTHORIZE_FAILED, wizard_db)
    set_action_id(session.token, "00000000-0000-0000-0000-000000000000", wizard_db)
    client.cookies.set(WIZARD_SESSION_COOKIE, session.token)
    client.cookies.set(LAST_SCAN_COOKIE, _HASH)
    scan = _mode_a_scan()
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.get("/authorize", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == f"/assessment/{_HASH}?wizard_note=expired"


def test_refresh_process_mid_run_is_noop_on_session_state(client: TestClient, wizard_db) -> None:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    loc = _through_authorize(client, wizard_db, scan)
    token = client.cookies.get(WIZARD_SESSION_COOKIE)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        client.get(loc)
        client.get(loc)
    session = load_session(token, wizard_db)
    assert session is not None
    assert session.current_step == STEP_AUTHORIZED


def test_find_session_by_action_id(wizard_db) -> None:
    session = create_session(_HASH, wizard_db)
    record = create_action_record(_HASH, "o/r", [], wizard_db)
    set_action_id(session.token, record.action_id, wizard_db)
    found = find_session_by_action_id(record.action_id, wizard_db)
    assert found is not None
    assert found.token == session.token


def test_mirror_scan_failed_persists_failure_reason_on_action_record(wizard_db) -> None:
    record = create_action_record(_HASH, "o/r", [], wizard_db)
    mirror_action_event(
        record.action_id,
        {"type": "scan_failed", "reason": "Invalid or expired PAT"},
        wizard_db,
    )
    from arguss.web.action_records import load_action_record

    loaded = load_action_record(record.action_id, wizard_db)
    assert loaded is not None
    assert loaded.status == "failed"
    assert loaded.failure_reason == "Invalid or expired PAT"
