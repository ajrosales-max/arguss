"""Step 1: wizard process page failure display (error card, header, action wording)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from arguss.settings import settings
from arguss.web.error_cards import wizard_remediation_failed_card_context
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict

_HASH = "wizard-failure-step1-hash"
_TEST_PAT = "github_pat_test_token_1234567890abcdef"
_STREAM_PARTIAL = (
    Path(__file__).resolve().parents[2]
    / "arguss"
    / "web"
    / "templates"
    / "partials"
    / "_wizard_process_stream.html"
)


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


def _process_page_html(client: TestClient, wizard_db) -> str:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(
            dashboard_mod,
            "register_scan_stream",
            new=mock.AsyncMock(return_value=("scan-fail-ux-1", mock.MagicMock())),
        ),
        mock.patch.object(dashboard_mod, "run_scan_background", new=mock.AsyncMock()),
        mock.patch.object(dashboard_mod, "attach_background_task", new=mock.AsyncMock()),
    ):
        client.post(f"/assessment/{_HASH}/plan", follow_redirects=False)
        client.post(
            "/select",
            data={"selected_candidate_ids": ["cand-left-pad-001"]},
            follow_redirects=False,
        )
        start = client.post("/authorize", data={"pat": _TEST_PAT}, follow_redirects=False)
        page = client.get(start.headers["location"])
    assert page.status_code == status.HTTP_200_OK
    return page.text


def test_wizard_remediation_failed_card_context_uses_action_wording() -> None:
    ctx = wizard_remediation_failed_card_context(
        scan_hash=_HASH,
        message="Invalid or expired PAT",
    )
    assert ctx["error_title"] == "Remediation failed"
    assert ctx["error_message"] == "Invalid or expired PAT"
    assert ctx["error_action"]["label"] == "← Back to authorize"
    assert ctx["error_action"]["url"] == "/authorize"
    assert ctx["error_secondary_action"]["url"] == f"/assessment/{_HASH}"
    assert "Retry with a different token" in ctx["error_suggestions"][2]
    assert ctx["error_kind"] == "network"


def test_process_page_renders_failure_error_card_shell(client: TestClient, wizard_db) -> None:
    html = _process_page_html(client, wizard_db)
    assert 'id="process-failure-card"' in html
    assert 'id="process-page-title"' in html
    assert 'id="process-page-subtitle"' in html
    assert "error-card" in html
    assert "Remediation failed" in html
    assert "← Back to authorize" in html
    assert 'href="/authorize"' in html
    assert f'href="/assessment/{_HASH}"' in html
    assert "Back to assessment" in html


def test_wizard_stream_partial_uses_action_failure_handler() -> None:
    partial = _STREAM_PARTIAL.read_text()
    assert "function showActionFailure" in partial
    assert "showActionFailure(d.reason)" in partial
    assert "Remediation failed" in partial
    assert "remediation action did not complete" in partial
    assert "Scan failed:" not in partial
    scan_failed_idx = partial.index("case 'scan_failed':")
    scan_failed_block = partial[scan_failed_idx : scan_failed_idx + 200]
    assert "scan failed" not in scan_failed_block.lower().replace("showactionfailure", "")


def test_process_page_initial_header_shows_in_progress(client: TestClient, wizard_db) -> None:
    html = _process_page_html(client, wizard_db)
    assert "Remediation in progress" in html
    assert "Opening pull requests" in html
