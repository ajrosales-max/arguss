"""Gate "View full results" on merge terminality + Arguss spinner (process page).

The merge panel (_action_run_progress.html) exposes data-terminal on every
HTMX poll swap; the process stream partial keeps the results CTA disabled and
the spinner visible until the panel reports ANY terminal state (merged or an
escalation end-state), so a stalled or escalated merge never traps the user.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from arguss.settings import settings
from arguss.web.action_runs import (
    TERMINAL_CANDIDATE_STATES,
    add_action_run_candidate,
    create_action_run,
    mark_action_run_completed,
    update_action_run_candidate,
)
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict
from tests.web.session_helpers import make_session_client, seed_github_installation

_TEMPLATES = Path(__file__).resolve().parents[2] / "arguss" / "web" / "templates"
_STREAM_PARTIAL = _TEMPLATES / "partials" / "_wizard_process_stream.html"
_PROGRESS_PARTIAL = _TEMPLATES / "partials" / "_action_run_progress.html"
_PROCESS_TEMPLATE = _TEMPLATES / "process.html"
_BASE_CSS = _TEMPLATES.parent / "static" / "css" / "base.css"

_HASH = "merge-gate-hash"
_TEST_INSTALLATION_ID = 12345


@pytest.fixture
def partial_client() -> TestClient:
    return TestClient(api_app)


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "merge-gate.db"
    monkeypatch.setattr(dashboard_mod.settings, "db_path", path)
    return path


def _cached_scan() -> dict[str, Any]:
    return {
        "scan_meta": {"repo_display": "expressjs/express", "mode": "C", "ref": "main"},
        "entries": [],
        "summary": {"total_findings": 0, "total_candidates": 0},
    }


def _progress_html(client: TestClient, run_id: str) -> str:
    with mock.patch.object(dashboard_mod, "_load_cached_results", return_value=_cached_scan()):
        response = client.get(f"/dashboard/action-run/{run_id}")
    assert response.status_code == status.HTTP_200_OK
    return response.text


# --- server-rendered terminal marker on the merge panel ---


def test_progress_partial_marks_non_terminal_run(partial_client: TestClient, db: Path) -> None:
    run = create_action_run("scan-hash", "C", db, scan_ref="main")
    add_action_run_candidate(run.id, "c1", "left-pad", "1.3.0", "1.3.1", db, state="ci_running")

    html = _progress_html(partial_client, run.id)
    assert 'data-terminal="false"' in html
    assert "Waiting on CI / auto-merge" in html


def test_progress_partial_marks_terminal_when_merged(partial_client: TestClient, db: Path) -> None:
    run = create_action_run("scan-hash", "C", db)
    cand = add_action_run_candidate(run.id, "c1", "pkg", "1", "2", db, pr_number=1)
    update_action_run_candidate(cand.id, db, state="merged")
    mark_action_run_completed(run.id, db)

    html = _progress_html(partial_client, run.id)
    assert 'data-terminal="true"' in html


@pytest.mark.parametrize("escalation_state", ["ci_failed", "timed_out"])
def test_progress_partial_marks_terminal_on_escalation(
    partial_client: TestClient,
    db: Path,
    escalation_state: str,
) -> None:
    """Escalation end-states are terminal too — the user must not stay gated."""
    run = create_action_run("scan-hash", "C", db)
    add_action_run_candidate(run.id, "c1", "pkg", "1", "2", db, state=escalation_state)

    html = _progress_html(partial_client, run.id)
    assert 'data-terminal="true"' in html


def test_terminal_states_cover_success_and_all_escalations() -> None:
    """The gate relies on is_action_run_terminal treating escalations as terminal."""
    assert {
        "merged",
        "ci_failed",
        "no_checks",
        "sha_conflict",
        "timed_out",
        "killed",
        "head_sha_unresolved",
        "pr_only",
    } <= set(TERMINAL_CANDIDATE_STATES)


# --- client gating logic in the stream partial ---


def _stream_js() -> str:
    return _STREAM_PARTIAL.read_text()


def _snippet(source: str, start_marker: str, end_marker: str) -> str:
    start = source.index(start_marker)
    return source[start : source.index(end_marker, start)]


def test_results_link_disabled_via_aria_and_click_prevention() -> None:
    js = _stream_js()
    assert "stream-results-link" in js
    assert "setAttribute('aria-disabled', 'true')" in js
    assert "ev.preventDefault()" in js


def test_gate_wired_on_htmx_after_swap_reading_data_terminal() -> None:
    js = _stream_js()
    handler = _snippet(js, "htmx:afterSwap", "function failureSuggestions")
    assert "dataset.terminal" in handler
    assert "releaseMergeGate()" in handler
    assert "applyMergeGate()" in handler
    # Any terminal state re-enables — the handler must not special-case a
    # success state like 'merged'.
    assert "'merged'" not in handler


def test_show_completion_does_not_enable_results_for_auto_merge_runs() -> None:
    js = _stream_js()
    body = _snippet(js, "function showCompletion", "function applyHydration")
    assert "expectsAutoMerge()" in body
    assert "applyMergeGate()" in body
    assert "releaseMergeGate()" in body
    # The old unconditional hide is gone from showCompletion.
    assert "spinner.hidden = true" not in body


def test_pr_only_runs_keep_current_behavior() -> None:
    """No auto-merge track -> results CTA enabled on PR-open completion."""
    js = _stream_js()
    mount = _snippet(js, "function mountActionRunProgress", "function showCompletion")
    assert "if (expectsAutoMerge()) applyMergeGate()" in mount


def test_hydration_reload_mid_merge_arms_gate_before_completion() -> None:
    js = _stream_js()
    body = _snippet(js, "function applyHydration", "function stopHydrationPoll")
    gate_idx = body.index("applyMergeGate()")
    completion_idx = body.index("showCompletion(h.scan_complete)")
    assert gate_idx < completion_idx


def test_release_gate_when_no_merge_run_was_created() -> None:
    """results_ready without an action_run_id must not leave the gate stuck."""
    js = _stream_js()
    handler = _snippet(js, "case 'results_ready':", "case 'scan_failed':")
    assert "releaseMergeGate()" in handler


def test_merge_wait_copy_present() -> None:
    assert "Waiting on CI / auto-merge…" in _stream_js()


def test_view_prs_on_github_never_disabled() -> None:
    process = _PROCESS_TEMPLATE.read_text()
    prs_anchor = _snippet(process, "https://github.com/{{ github_owner }}", "</a>")
    assert "aria-disabled" not in prs_anchor
    assert 'id="' not in prs_anchor  # no hook for JS to target it
    js = _stream_js()
    # The only element the gate disables is the results link.
    for line in js.splitlines():
        if "setAttribute('aria-disabled'" in line:
            assert "resultsLink" in line


# --- spinner actually paints in this state-driven phase ---


def _rendered_process_page(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[str, Any]:
    monkeypatch.setattr(settings, "db_path", tmp_path / "wizard.db")
    client = make_session_client(monkeypatch)
    scan = _cached_scan_dict(
        entries=[_cached_entry(package="left-pad", tier="auto_merge")],
        mode="A",
    )
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(
            dashboard_mod,
            "register_scan_stream",
            new=mock.AsyncMock(return_value=("scan-gate-1", mock.MagicMock())),
        ),
        mock.patch.object(dashboard_mod, "run_scan_background", new=mock.AsyncMock()),
        mock.patch.object(dashboard_mod, "attach_background_task", new=mock.AsyncMock()),
    ):
        client.post(f"/assessment/{_HASH}/plan", follow_redirects=False)
        client.post(
            "/select",
            data={
                "selected_candidate_ids": ["cand-left-pad-001"],
                "auto_merge_candidate_ids": ["cand-left-pad-001"],
            },
            follow_redirects=False,
        )
        seed_github_installation(client, _TEST_INSTALLATION_ID)
        start = client.post("/authorize", follow_redirects=False)
        process_path = start.headers["location"]
        page = client.get(process_path)
    assert page.status_code == status.HTTP_200_OK
    return page.text, (client, process_path)


def test_process_page_spinner_is_logo_and_not_htmx_gated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    html, _ = _rendered_process_page(monkeypatch, tmp_path)
    spinner_block = html.split('id="spinner"', 1)[1][:600]
    assert "loading-indicator--visible" in spinner_block
    assert "htmx-indicator" not in spinner_block
    assert "loading-logo" in spinner_block


def test_visible_indicator_variant_css_paints() -> None:
    css = _BASE_CSS.read_text()
    rule = re.search(r"\.loading-indicator--visible\s*\{([^}]*)\}", css)
    assert rule is not None
    assert "display: flex" in rule.group(1)
    assert "display: none" not in rule.group(1)


def test_disabled_anchor_button_styling_exists() -> None:
    css = _BASE_CSS.read_text()
    rule = re.search(r"\.btn\[aria-disabled=\"true\"\]\s*\{([^}]*)\}", css)
    assert rule is not None
    assert "cursor: not-allowed" in rule.group(1)


# --- reload/hydration mid-merge renders the gated inputs ---


def test_reload_mid_merge_embeds_auto_merge_track_and_non_terminal_panel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """After a reload mid-merge, the page embeds tracks_auto_merge + the run id,
    and the mounted panel reports data-terminal=false — the inputs the client
    gate consumes to render disabled + spinner instead of an enabled button."""
    from arguss.web.action_records import mirror_action_event
    from arguss.web.wizard_session import WIZARD_SESSION_COOKIE, load_session

    _, (client, process_path) = _rendered_process_page(monkeypatch, tmp_path)
    db = settings.db_path
    token = client.cookies.get(WIZARD_SESSION_COOKIE)
    session = load_session(token, db)
    assert session is not None and session.action_id

    # Simulate: PR opening finished (record terminal) while the merge loop is
    # still waiting on CI (action run non-terminal).
    mirror_action_event(
        session.action_id,
        {"type": "scan_complete", "total": 1, "succeeded": 1, "failed": 0, "skipped": 0},
        db,
    )
    run = create_action_run(
        "scan-hash",
        "C",
        db,
        scan_ref="main",
        wizard_action_id=session.action_id,
    )
    add_action_run_candidate(run.id, "c1", "left-pad", "1.3.0", "1.3.1", db, state="ci_running")

    scan = _cached_scan_dict(
        entries=[_cached_entry(package="left-pad", tier="auto_merge")],
        mode="A",
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        page = client.get(process_path)
    assert page.status_code == status.HTTP_200_OK
    assert '"tracks_auto_merge": true' in page.text
    assert f'"action_run_id": "{run.id}"' in page.text
    assert '"terminal": true' in page.text

    with mock.patch.object(dashboard_mod, "_load_cached_results", return_value=_cached_scan()):
        panel = client.get(f"/dashboard/action-run/{run.id}")
    assert 'data-terminal="false"' in panel.text
