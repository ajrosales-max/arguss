"""Integration tests for remediation wizard (phase 3)."""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict

_HASH = "wizard-demo-hash"
_TEST_PAT = "github_pat_test_token_1234567890abcdef"


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def _mode_a_scan(*entries: dict[str, Any]) -> dict[str, Any]:
    return _cached_scan_dict(entries=list(entries), mode="A")


def test_assessment_page_has_plan_cta(client: TestClient) -> None:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get(f"/results/{_HASH}")
    assert response.status_code == status.HTTP_200_OK
    assert "Plan remediation" in response.text
    assert f"/results/{_HASH}/plan" in response.text


def test_plan_page_renders_selection_ui(client: TestClient) -> None:
    scan = _mode_a_scan(
        _cached_entry(package="minimatch", tier="auto_merge"),
        _cached_entry(package="lodash", tier="review_required"),
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get(f"/results/{_HASH}/plan")
    assert response.status_code == status.HTTP_200_OK
    assert 'name="selected_candidate_ids"' in response.text
    assert 'id="candidate-selection"' in response.text


def test_plan_page_auto_merge_selectable(client: TestClient) -> None:
    scan = _mode_a_scan(_cached_entry(package="safe-pkg", tier="auto_merge"))
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get(f"/results/{_HASH}/plan")
    marker = 'value="cand-safe-pkg-001"'
    assert marker in response.text
    snippet = response.text.split(marker, 1)[1][:220]
    assert "disabled" not in snippet
    assert "checked" in snippet


def test_plan_page_review_decline_checkboxes_disabled(client: TestClient) -> None:
    scan = _mode_a_scan(
        _cached_entry(package="review-pkg", tier="review_required"),
        _cached_entry(package="decline-pkg", tier="decline"),
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get(f"/results/{_HASH}/plan")
    for pkg in ("review-pkg", "decline-pkg"):
        marker = f'value="cand-{pkg}-001"'
        idx = response.text.index(marker)
        assert "disabled" in response.text[idx : idx + 200]


def test_authorize_page_shows_selection_summary(client: TestClient) -> None:
    scan = _mode_a_scan(
        _cached_entry(package="pkg-a", tier="auto_merge"),
        _cached_entry(package="pkg-b", tier="auto_merge"),
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.post(
            f"/results/{_HASH}/authorize",
            data={
                "selected_candidate_ids": ["cand-pkg-a-001", "cand-pkg-b-001"],
            },
        )
    assert response.status_code == status.HTTP_200_OK
    assert "pkg-a" in response.text
    assert "pkg-b" in response.text
    assert "selection-summary-list" in response.text


def test_authorize_page_shows_pat_instructions_with_both_permissions(client: TestClient) -> None:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.post(
            f"/results/{_HASH}/authorize",
            data={"selected_candidate_ids": ["cand-left-pad-001"]},
        )
    text = response.text
    assert "Contents" in text
    assert "Pull requests" in text


def test_authorize_page_names_target_repo(client: TestClient) -> None:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.post(
            f"/results/{_HASH}/authorize",
            data={"selected_candidate_ids": ["cand-left-pad-001"]},
        )
    assert "expressjs/express" in response.text


def test_selection_carries_from_plan_to_authorize(client: TestClient) -> None:
    scan = _mode_a_scan(
        _cached_entry(package="only-one", tier="auto_merge"),
        _cached_entry(package="skip-me", tier="auto_merge"),
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.post(
            f"/results/{_HASH}/authorize",
            data={"selected_candidate_ids": ["cand-only-one-001"]},
        )
    assert "only-one" in response.text
    idx = response.text.find("selection-summary-list")
    assert idx != -1
    summary_block = response.text[idx : idx + 500]
    assert "skip-me" not in summary_block


def test_process_page_streams_only_selected_rows(client: TestClient) -> None:
    scan = _mode_a_scan(
        _cached_entry(package="a", tier="auto_merge"),
        _cached_entry(package="b", tier="auto_merge"),
    )
    selected = ["cand-a-001"]
    captured: dict[str, object] = {}

    async def fake_run_scan_background(scan_id, **kwargs):
        captured.update(kwargs)

    async def fake_register():
        return ("scan-test-123", mock.AsyncMock())

    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(
            dashboard_mod,
            "register_scan_stream",
            new=mock.AsyncMock(return_value=("scan-test-123", mock.MagicMock())),
        ),
        mock.patch.object(
            dashboard_mod, "run_scan_background", side_effect=fake_run_scan_background
        ),
        mock.patch.object(dashboard_mod, "attach_background_task", new=mock.AsyncMock()),
    ):
        response = client.post(
            f"/results/{_HASH}/process/start",
            data={"pat": _TEST_PAT, "selected_candidate_ids": selected},
            follow_redirects=False,
        )
        assert response.status_code == status.HTTP_303_SEE_OTHER
        assert "scan-test-123" in response.headers["location"]
        assert captured.get("selected_candidate_ids") == selected

        page = client.get(response.headers["location"])
        assert page.status_code == status.HTTP_200_OK
        assert "scan-test-123" in page.text
