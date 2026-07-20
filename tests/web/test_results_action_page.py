"""Tests for /results/{action_id} permalink."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from arguss.settings import settings
from arguss.web.action_records import (
    PROutcome,
    create_action_record,
    finalize_action_record,
    load_action_record,
    mirror_action_event,
    update_pr_outcome,
)
from arguss.web.wizard_session import WIZARD_SESSION_COOKIE, load_session
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict

_HASH = "action-page-hash"
_TEST_INSTALLATION_ID = 12345
_UNKNOWN_ACTION_ID = "a0000000-0000-4000-8000-000000000001"


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


@pytest.fixture
def wizard_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    db = tmp_path / "wizard.db"
    monkeypatch.setattr(settings, "db_path", db)
    return db


def _mode_a_scan(*entries: dict[str, Any]) -> dict[str, Any]:
    scan = _cached_scan_dict(entries=list(entries), mode="A")
    scan["scan_meta"] = {
        "mode": "A",
        "repo_display": "owner/repo",
        "ref": "main",
        "repo_url": "https://github.com/owner/repo",
    }
    return scan


def _sample_record(db: Path):
    record = create_action_record(_HASH, "owner/repo", ["c1"], db)
    update_pr_outcome(
        record.action_id,
        PROutcome(
            "c1",
            "left-pad",
            "1.0.0",
            "1.0.1",
            "patch",
            "opened",
            pr_number=42,
            pr_url="https://github.com/o/r/pull/42",
        ),
        db,
    )
    finalize_action_record(record.action_id, "completed", db)
    return load_action_record(record.action_id, db)


def test_results_action_page_renders_pr_list(client: TestClient, wizard_db: Path) -> None:
    record = _sample_record(wizard_db)
    assert record is not None
    with mock.patch.object(
        dashboard_mod,
        "load_scan_summary_for_action_page",
        return_value={
            "repo_display": "owner/repo",
            "ref": "main",
            "risk_score": 62,
            "findings_total": 1,
            "candidate_total": 1,
        },
    ):
        r = client.get(f"/results/{record.action_id}")
    assert r.status_code == 200
    assert "left-pad" in r.text
    assert "PR #42" in r.text


def test_results_action_page_shows_opened_count_in_header(
    client: TestClient, wizard_db: Path
) -> None:
    record = _sample_record(wizard_db)
    assert record is not None
    with mock.patch.object(dashboard_mod, "load_scan_summary_for_action_page", return_value=None):
        r = client.get(f"/results/{record.action_id}")
    assert "1 PR opened" in r.text


def test_results_action_page_shows_short_action_id(client: TestClient, wizard_db: Path) -> None:
    record = _sample_record(wizard_db)
    assert record is not None
    with mock.patch.object(dashboard_mod, "load_scan_summary_for_action_page", return_value=None):
        r = client.get(f"/results/{record.action_id}")
    assert record.action_id[:8] in r.text


def test_results_action_page_links_to_full_assessment(client: TestClient, wizard_db: Path) -> None:
    record = _sample_record(wizard_db)
    assert record is not None
    with mock.patch.object(dashboard_mod, "load_scan_summary_for_action_page", return_value=None):
        r = client.get(f"/results/{record.action_id}")
    assert f"/assessment/{_HASH}" in r.text


def test_results_action_page_404_for_unknown_action_id(client: TestClient, wizard_db: Path) -> None:
    r = client.get(f"/results/{_UNKNOWN_ACTION_ID}")
    assert r.status_code == 404


def test_results_action_page_no_session_required(client: TestClient, wizard_db: Path) -> None:
    record = _sample_record(wizard_db)
    assert record is not None
    client.cookies.clear()
    with mock.patch.object(dashboard_mod, "load_scan_summary_for_action_page", return_value=None):
        r = client.get(f"/results/{record.action_id}")
    assert r.status_code == 200


def test_results_action_page_renders_partial_status_banner_on_partial(
    client: TestClient,
    wizard_db: Path,
) -> None:
    record = create_action_record(_HASH, "owner/repo", [], wizard_db)
    finalize_action_record(record.action_id, "partial", wizard_db)
    with mock.patch.object(dashboard_mod, "load_scan_summary_for_action_page", return_value=None):
        r = client.get(f"/results/{record.action_id}")
    assert "partially complete" in r.text.lower()


def _through_authorize(client: TestClient, scan: dict[str, Any]) -> None:
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        client.post(f"/assessment/{_HASH}/plan", follow_redirects=False)
        client.post(
            "/select",
            data={"selected_candidate_ids": ["cand-left-pad-001"]},
            follow_redirects=False,
        )


def test_post_authorize_creates_action_record(client: TestClient, wizard_db: Path) -> None:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    _through_authorize(client, scan)
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(
            dashboard_mod,
            "register_scan_stream",
            new=mock.AsyncMock(return_value=("sid", mock.MagicMock())),
        ),
        mock.patch.object(dashboard_mod, "run_scan_background", new=mock.AsyncMock()),
        mock.patch.object(dashboard_mod, "attach_background_task", new=mock.AsyncMock()),
    ):
        client.post(
            "/authorize", data={"installation_id": _TEST_INSTALLATION_ID}, follow_redirects=False
        )
    token = client.cookies[WIZARD_SESSION_COOKIE]
    session = load_session(token, wizard_db)
    assert session is not None and session.action_id
    record = load_action_record(session.action_id, wizard_db)
    assert record is not None
    assert record.scan_hash == _HASH
    assert record.status == "pending"


def test_post_authorize_sets_action_id_on_session(client: TestClient, wizard_db: Path) -> None:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    _through_authorize(client, scan)
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(
            dashboard_mod,
            "register_scan_stream",
            new=mock.AsyncMock(return_value=("stream-only", mock.MagicMock())),
        ),
        mock.patch.object(dashboard_mod, "run_scan_background", new=mock.AsyncMock()),
        mock.patch.object(dashboard_mod, "attach_background_task", new=mock.AsyncMock()),
    ):
        client.post(
            "/authorize", data={"installation_id": _TEST_INSTALLATION_ID}, follow_redirects=False
        )
    session = load_session(client.cookies[WIZARD_SESSION_COOKIE], wizard_db)
    assert session is not None
    assert session.action_id != "stream-only"
    uuid.UUID(session.action_id)


def test_pr_opened_event_updates_action_record(wizard_db: Path) -> None:
    record = create_action_record(_HASH, "o/r", [], wizard_db)
    mirror_action_event(
        record.action_id,
        {
            "type": "action_completed",
            "candidate_id": "c1",
            "status": "opened",
            "package": "pkg",
            "from": "1",
            "to": "2",
            "fix_kind": "patch",
            "pr_number": 9,
            "pr_url": "https://github.com/o/r/pull/9",
        },
        wizard_db,
    )
    loaded = load_action_record(record.action_id, wizard_db)
    assert loaded is not None
    assert loaded.pr_outcomes[0].status == "opened"
    assert loaded.pr_outcomes[0].pr_number == 9


def test_scan_completed_event_finalizes_action_record(wizard_db: Path) -> None:
    record = create_action_record(_HASH, "o/r", [], wizard_db)
    mirror_action_event(
        record.action_id,
        {"type": "scan_complete", "total": 1, "succeeded": 1, "failed": 0, "skipped": 0},
        wizard_db,
    )
    loaded = load_action_record(record.action_id, wizard_db)
    assert loaded is not None and loaded.status == "completed"


def test_process_page_completion_cta_uses_action_id(client: TestClient, wizard_db: Path) -> None:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(
            dashboard_mod,
            "register_scan_stream",
            new=mock.AsyncMock(return_value=("sid", mock.MagicMock())),
        ),
        mock.patch.object(dashboard_mod, "run_scan_background", new=mock.AsyncMock()),
        mock.patch.object(dashboard_mod, "attach_background_task", new=mock.AsyncMock()),
    ):
        _through_authorize(client, scan)
        start = client.post(
            "/authorize", data={"installation_id": _TEST_INSTALLATION_ID}, follow_redirects=False
        )
        page = client.get(start.headers["location"])
    session = load_session(client.cookies[WIZARD_SESSION_COOKIE], wizard_db)
    assert session is not None and session.action_id
    assert f"/results/{session.action_id}" in page.text


def test_action_failure_during_streaming_marks_outcome_failed(wizard_db: Path) -> None:
    record = create_action_record(_HASH, "o/r", [], wizard_db)
    mirror_action_event(
        record.action_id,
        {
            "type": "action_completed",
            "candidate_id": "c1",
            "status": "failed",
            "package": "pkg",
            "from": "1",
            "to": "2",
            "fix_kind": "patch",
            "reason": "rate limited",
        },
        wizard_db,
    )
    loaded = load_action_record(record.action_id, wizard_db)
    assert loaded is not None
    assert loaded.pr_outcomes[0].status == "failed"
    assert loaded.pr_outcomes[0].error == "rate limited"
