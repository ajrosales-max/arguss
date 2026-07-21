"""Step 1: wizard process page failure display (error card, header, action wording)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.settings import settings
from arguss.web.error_cards import wizard_remediation_failed_card_context
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict
from tests.web.session_helpers import make_session_client, seed_github_installation

_HASH = "wizard-failure-step1-hash"
_TEST_INSTALLATION_ID = 12345
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
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    return make_session_client(monkeypatch)


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
        seed_github_installation(client, _TEST_INSTALLATION_ID)
        start = client.post("/authorize", follow_redirects=False)
        page = client.get(start.headers["location"])
    assert page.status_code == status.HTTP_200_OK
    return page.text


def test_wizard_remediation_failed_card_context_uses_action_wording() -> None:
    message = "GitHub App authorization failed; reconnect arguss-bot and retry"
    ctx = wizard_remediation_failed_card_context(scan_hash=_HASH, message=message)
    assert ctx["error_title"] == "Remediation failed"
    assert ctx["error_message"] == message
    assert ctx["error_action"]["label"] == "← Back to authorize"
    assert ctx["error_action"]["url"] == "/authorize"
    assert ctx["error_secondary_action"]["url"] == f"/assessment/{_HASH}"
    assert "Reconnect arguss-bot" in ctx["error_suggestions"][2]
    assert ctx["error_kind"] == "network"


def test_remediation_failed_card_not_installed_shows_fork_guidance() -> None:
    from arguss.web.github_action import APP_NOT_INSTALLED_DETAIL

    ctx = wizard_remediation_failed_card_context(scan_hash=_HASH, message=APP_NOT_INSTALLED_DETAIL)
    assert ctx["error_title"] == "Remediation failed"
    assert ctx["error_message"] == APP_NOT_INSTALLED_DETAIL
    assert ctx["error_kind"] == "network"
    assert ctx["error_action"]["url"] == "/authorize"
    joined = " ".join(ctx["error_suggestions"])
    assert "fork it and scan your fork" in joined
    assert "install arguss-bot on this repository" in joined
    # Fork guidance replaces, not extends, the generic reconnect suggestions.
    assert "Reconnect arguss-bot" not in joined


def test_stream_partial_mirrors_not_installed_suggestions() -> None:
    partial = _STREAM_PARTIAL.read_text()
    assert "isn't installed on this repository" in partial
    assert "fork it and scan your fork" in partial
    assert (
        "install arguss-bot on this repository (or check its repository access) and retry"
        in partial
    )


def test_persisted_outcome_keeps_mapped_not_installed_reason() -> None:
    from arguss.web.action_records import _outcome_from_completed
    from arguss.web.github_action import APP_NOT_INSTALLED_DETAIL

    event = {
        "type": "action_completed",
        "candidate_id": "cand-1",
        "status": "failed",
        "reason": APP_NOT_INSTALLED_DETAIL,
        "package": "left-pad",
        "from": "1.3.0",
        "to": "1.3.1",
        "fix_kind": "patch",
    }
    outcome = _outcome_from_completed(event)
    assert outcome.status == "failed"
    assert outcome.error == APP_NOT_INSTALLED_DETAIL
    assert "Resource not accessible by integration" not in outcome.error


def test_pat_era_retry_copy_is_gone_from_enact_surfaces() -> None:
    """Step 5 sweep: no PAT-era failure/retry strings on enact/error surfaces."""
    import inspect

    from arguss.web import error_cards

    surfaces = {
        "wizard process stream partial": _STREAM_PARTIAL.read_text(),
        "error_cards module": inspect.getsource(error_cards),
    }
    for name, text in surfaces.items():
        lower = text.lower()
        assert "retry with a different token" not in lower, name
        assert "confirm the pat is valid" not in lower, name
        assert "invalid or expired pat" not in lower, name
        assert "pat lacks repo scope" not in lower, name


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


def test_remediation_failed_card_concrete_reason_drops_dangling_bullet() -> None:
    ctx = wizard_remediation_failed_card_context(
        scan_hash=_HASH, message="Action failed: RuntimeError"
    )
    assert ctx["error_suggestions"] == ["Return to authorize to try again"]


def test_remediation_failed_card_no_reason_keeps_generic_bullets() -> None:
    ctx = wizard_remediation_failed_card_context(scan_hash=_HASH)
    assert ctx["error_suggestions"] == [
        "Review the message above for the specific cause",
        "Return to authorize to try again",
    ]


def test_stream_partial_drops_dangling_bullet_for_concrete_reason() -> None:
    partial = _STREAM_PARTIAL.read_text()
    assert "if (reason) {" in partial
    assert "return ['Return to authorize to try again'];" in partial
    # The phantom-message bullet survives only as the no-reason fallback.
    assert partial.count("Review the message above for the specific cause") == 1


def test_stream_partial_failed_hydration_uses_derived_reasons() -> None:
    partial = _STREAM_PARTIAL.read_text()
    assert "function distinctFailureReasons" in partial
    assert "showActionFailure(h.failure_reason || distinctFailureReasons(h.pr_outcomes))" in partial


def test_stream_partial_keeps_candidate_rows_visible_on_failure() -> None:
    partial = _STREAM_PARTIAL.read_text()
    assert "progress.hidden = true" not in partial


def test_stream_partial_suggestions_follow_reason_text() -> None:
    # Fork/install suggestions key off the rendered reason text (the
    # not-installed marker); they are not wired separately for the failed
    # state, so passing the real reason lights them up automatically.
    partial = _STREAM_PARTIAL.read_text()
    assert "failureSuggestions(reasonText)" in partial
    assert "isn't installed on this repository" in partial
    assert "fork it and scan your fork" in partial


def test_process_page_initial_header_shows_in_progress(client: TestClient, wizard_db) -> None:
    html = _process_page_html(client, wizard_db)
    assert "Remediation in progress" in html
    assert "Opening pull requests" in html
