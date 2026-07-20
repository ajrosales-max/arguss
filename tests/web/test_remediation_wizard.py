"""Integration tests for remediation wizard UI (phases 3–4)."""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.settings import settings
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict
from tests.web.session_helpers import make_session_client, seed_github_installation

_HASH = "wizard-demo-hash"
_TEST_INSTALLATION_ID = 12345


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    return make_session_client(monkeypatch)


@pytest.fixture
def wizard_db(monkeypatch: pytest.MonkeyPatch, tmp_path):
    db = tmp_path / "wizard.db"
    monkeypatch.setattr(settings, "db_path", db)
    return db


def _mode_a_scan(*entries: dict[str, Any]) -> dict[str, Any]:
    return _cached_scan_dict(entries=list(entries), mode="A")


def _open_select(client: TestClient, scan: dict[str, Any]) -> Any:
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        client.post(f"/assessment/{_HASH}/plan", follow_redirects=True)
        return client.get("/select")


def _authorize_via_select(client: TestClient, scan: dict[str, Any], selected_ids: list[str]) -> Any:
    _open_select(client, scan)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        return client.post(
            "/select",
            data={"selected_candidate_ids": selected_ids},
            follow_redirects=True,
        )


def test_assessment_page_has_plan_cta(client: TestClient) -> None:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get(f"/assessment/{_HASH}")
    assert response.status_code == status.HTTP_200_OK
    assert "Plan remediation" in response.text
    assert f"/assessment/{_HASH}/plan" in response.text


def test_plan_page_renders_selection_ui(client: TestClient, wizard_db) -> None:
    scan = _mode_a_scan(
        _cached_entry(package="minimatch", tier="auto_merge"),
        _cached_entry(package="lodash", tier="review_required"),
    )
    response = _open_select(client, scan)
    assert response.status_code == status.HTTP_200_OK
    assert 'name="selected_candidate_ids"' in response.text
    assert 'id="candidate-selection"' in response.text


def test_plan_page_auto_merge_selectable(client: TestClient, wizard_db) -> None:
    scan = _mode_a_scan(_cached_entry(package="safe-pkg", tier="auto_merge"))
    response = _open_select(client, scan)
    marker = 'value="cand-safe-pkg-001"'
    assert marker in response.text
    snippet = response.text.split(marker, 1)[1][:220]
    assert "disabled" not in snippet
    assert "checked" in snippet


def test_plan_page_review_decline_checkboxes_disabled(
    client: TestClient, wizard_db, allow_decline_override
) -> None:
    allow_decline_override(False)
    scan = _mode_a_scan(
        _cached_entry(package="review-pkg", tier="review_required"),
        _cached_entry(package="decline-pkg", tier="decline"),
    )
    response = _open_select(client, scan)
    review_marker = 'value="cand-review-pkg-001"'
    review_snippet = response.text.split(review_marker, 1)[1][:200]
    assert "disabled" not in review_snippet
    decline_marker = 'value="cand-decline-pkg-001"'
    decline_snippet = response.text.split(decline_marker, 1)[1][:200]
    assert "disabled" in decline_snippet


def test_authorize_page_shows_selection_summary(client: TestClient, wizard_db) -> None:
    scan = _mode_a_scan(
        _cached_entry(package="pkg-a", tier="auto_merge"),
        _cached_entry(package="pkg-b", tier="auto_merge"),
    )
    response = _authorize_via_select(client, scan, ["cand-pkg-a-001", "cand-pkg-b-001"])
    assert response.status_code == status.HTTP_200_OK
    assert "pkg-a" in response.text
    assert "pkg-b" in response.text
    assert "selection-summary-list" in response.text


def test_authorize_page_shows_pat_instructions_with_both_permissions(
    client: TestClient, wizard_db
) -> None:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    response = _authorize_via_select(client, scan, ["cand-left-pad-001"])
    assert "Contents" in response.text
    assert "Pull requests" in response.text


def test_authorize_page_names_target_repo(client: TestClient, wizard_db) -> None:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    response = _authorize_via_select(client, scan, ["cand-left-pad-001"])
    assert "expressjs/express" in response.text


def test_selection_carries_from_plan_to_authorize(client: TestClient, wizard_db) -> None:
    scan = _mode_a_scan(
        _cached_entry(package="only-one", tier="auto_merge"),
        _cached_entry(package="skip-me", tier="auto_merge"),
    )
    response = _authorize_via_select(client, scan, ["cand-only-one-001"])
    assert "only-one" in response.text
    idx = response.text.find("selection-summary-list")
    assert idx != -1
    assert "skip-me" not in response.text[idx : idx + 500]


def test_process_page_streams_only_selected_rows(client: TestClient, wizard_db) -> None:
    scan = _mode_a_scan(
        _cached_entry(package="a", tier="auto_merge"),
        _cached_entry(package="b", tier="auto_merge"),
    )
    selected = ["cand-a-001"]
    captured: dict[str, object] = {}

    async def fake_run_scan_background(scan_id, **kwargs):
        captured.update(kwargs)

    _authorize_via_select(client, scan, selected)
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(
            dashboard_mod,
            "register_scan_stream",
            new=mock.AsyncMock(return_value=("scan-test-123", mock.MagicMock())),
        ),
        mock.patch.object(
            dashboard_mod,
            "get_scan_stream_queue",
            new=mock.AsyncMock(return_value=mock.MagicMock()),
        ),
        mock.patch.object(
            dashboard_mod, "run_scan_background", side_effect=fake_run_scan_background
        ),
        mock.patch.object(dashboard_mod, "attach_background_task", new=mock.AsyncMock()),
    ):
        seed_github_installation(client, _TEST_INSTALLATION_ID)
        response = client.post("/authorize", follow_redirects=False)
        assert response.status_code == status.HTTP_303_SEE_OTHER
        assert "scan-test-123" in response.headers["location"]
        assert captured.get("selected_candidate_ids") == selected
        page = client.get(response.headers["location"])
        assert page.status_code == status.HTTP_200_OK
        assert "scan-test-123" in page.text


def test_plan_page_renders_findings_drilldown(client: TestClient, wizard_db) -> None:
    scan = _mode_a_scan(_cached_entry(package="minimatch", tier="auto_merge"))
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        plan = _open_select(client, scan)
        assessment = client.get(f"/assessment/{_HASH}")
    assert "findings-toggle" in plan.text
    assert "candidate-checkbox" in plan.text
    assert "findings-toggle" not in assessment.text
    assert "candidate-checkbox" not in assessment.text
