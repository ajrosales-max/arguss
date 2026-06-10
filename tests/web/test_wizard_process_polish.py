"""Template and stream partial tests for wizard process page polish."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict

_HASH = "wizard-polish-hash"
_TEST_PAT = "github_pat_test_token_1234567890abcdef"
_WIZARD_PARTIAL = (
    Path(__file__).resolve().parents[2]
    / "arguss"
    / "web"
    / "templates"
    / "partials"
    / "_wizard_process_stream.html"
)
_ACTION_PARTIAL = (
    Path(__file__).resolve().parents[2]
    / "arguss"
    / "web"
    / "templates"
    / "partials"
    / "_mode_c_stream.html"
)


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def _mode_a_scan(*entries: dict[str, Any]) -> dict[str, Any]:
    return _cached_scan_dict(entries=list(entries), mode="A")


def _process_page_html(client: TestClient) -> str:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(
            dashboard_mod,
            "register_scan_stream",
            new=mock.AsyncMock(return_value=("scan-polish-1", mock.MagicMock())),
        ),
        mock.patch.object(dashboard_mod, "run_scan_background", new=mock.AsyncMock()),
        mock.patch.object(dashboard_mod, "attach_background_task", new=mock.AsyncMock()),
    ):
        start = client.post(
            f"/results/{_HASH}/process/start",
            data={"pat": _TEST_PAT, "selected_candidate_ids": ["cand-left-pad-001"]},
            follow_redirects=False,
        )
        page = client.get(start.headers["location"])
    assert page.status_code == status.HTTP_200_OK
    return page.text


def test_process_page_row_shows_package_and_version_delta(client: TestClient) -> None:
    html = _process_page_html(client)
    assert "_wizard_process_stream.html" in html or "stream-package" in html
    partial = _WIZARD_PARTIAL.read_text()
    assert "stream-package" in partial
    assert "stream-version-delta" in partial
    assert "c.from || ''" in partial or "c.from" in partial
    assert (
        "data-candidate-id" not in html
        or "candidate_id" not in html.split("mode-c-action-list")[1][:400]
    )


def test_process_page_row_shows_pr_link_after_pr_opened() -> None:
    partial = _WIZARD_PARTIAL.read_text()
    assert "setPrLink" in partial
    assert "PR #" in partial
    assert "pr_url" in partial


def test_process_page_row_shows_failure_detail_on_failed() -> None:
    partial = _WIZARD_PARTIAL.read_text()
    assert "d.status === 'failed'" in partial
    assert "stream-detail" in partial


def test_process_page_no_auto_redirect_on_completion() -> None:
    partial = _WIZARD_PARTIAL.read_text()
    assert "case 'results_ready':" in partial
    results_idx = partial.index("case 'results_ready':")
    snippet = partial[results_idx : results_idx + 80]
    assert "window.location" not in snippet


def test_process_page_shows_view_results_button_on_completion(client: TestClient) -> None:
    html = _process_page_html(client)
    assert 'id="stream-complete"' in html
    assert 'id="stream-results-link"' in html
    assert "View full results" in html


def test_process_page_view_results_button_links_to_results_route(client: TestClient) -> None:
    html = _process_page_html(client)
    assert f'href="/results/{_HASH}"' in html


def test_action_page_behavior_unchanged(client: TestClient) -> None:
    response = client.get("/action")
    assert response.status_code == status.HTTP_200_OK
    text = response.text
    assert "_mode_c_stream.html" in text or "mode-c-action-icon" in text
    assert "_wizard_process_stream.html" not in text
    partial = _ACTION_PARTIAL.read_text()
    assert "redirectOnComplete" in partial
    assert "results_ready" in partial and "window.location.href" in partial


def test_process_page_uses_wizard_stream_partial_not_shared(client: TestClient) -> None:
    html = _process_page_html(client)
    assert "stream-fix-kind" in html or "stream-fix-kind" in _WIZARD_PARTIAL.read_text()
    assert "showCompletion" in _WIZARD_PARTIAL.read_text()
