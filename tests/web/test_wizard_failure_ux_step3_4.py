"""Step 3–4: honest completion breakdown on process and results pages."""

from __future__ import annotations

from pathlib import Path
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
from arguss.web.completion_summary import (
    OutcomeCounts,
    counts_from_pr_outcomes,
    format_completion_breakdown,
)
from arguss.web.wizard_session import (
    STEP_COMPLETED,
    create_session,
    find_session_by_action_id,
    set_action_id,
)

_HASH = "wizard-failure-step3-4-hash"
_STREAM_PARTIAL = (
    Path(__file__).resolve().parents[2]
    / "arguss"
    / "web"
    / "templates"
    / "partials"
    / "_wizard_process_stream.html"
)
_PROCESS_TEMPLATE = (
    Path(__file__).resolve().parents[2] / "arguss" / "web" / "templates" / "process.html"
)


@pytest.fixture
def wizard_db(monkeypatch: pytest.MonkeyPatch, tmp_path):
    db = tmp_path / "wizard.db"
    monkeypatch.setattr(settings, "db_path", db)
    return db


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def test_format_completion_breakdown_clean_run() -> None:
    assert (
        format_completion_breakdown(OutcomeCounts(opened=18, already_exists=0, failed=0, skipped=0))
        == "18 PRs opened"
    )
    assert (
        format_completion_breakdown(OutcomeCounts(opened=1, already_exists=0, failed=0, skipped=0))
        == "1 PR opened"
    )


def test_format_completion_breakdown_honest_split() -> None:
    counts = OutcomeCounts(opened=18, already_exists=3, failed=1, skipped=1)
    assert format_completion_breakdown(counts) == ("18 PRs opened · 3 already open · 2 failed")


def test_mirror_preserves_already_exists_status(wizard_db) -> None:
    record = create_action_record(_HASH, "owner/repo", ["c1"], wizard_db)
    mirror_action_event(
        record.action_id,
        {
            "type": "action_completed",
            "candidate_id": "c1",
            "status": "already_exists",
            "package": "left-pad",
            "from": "1.0.0",
            "to": "1.0.1",
            "fix_kind": "patch",
            "pr_number": 12,
            "pr_url": "https://github.com/o/r/pull/12",
        },
        wizard_db,
    )
    loaded = load_action_record(record.action_id, wizard_db)
    assert loaded is not None
    assert loaded.pr_outcomes[0].status == "already_exists"
    partial = _STREAM_PARTIAL.read_text()
    assert "if (st === 'already_exists') return 'already-exists';" in partial
    assert "d.status === 'already_exists'" in partial


def test_scan_complete_with_failures_still_completes_session(wizard_db) -> None:
    session = create_session(_HASH, wizard_db)
    record = create_action_record(_HASH, "owner/repo", ["c1", "c2"], wizard_db)
    set_action_id(session.token, record.action_id, wizard_db)
    mirror_action_event(
        record.action_id,
        {
            "type": "scan_complete",
            "total": 2,
            "succeeded": 1,
            "already_exists": 0,
            "failed": 1,
            "skipped": 0,
        },
        wizard_db,
    )
    linked = find_session_by_action_id(record.action_id, wizard_db)
    assert linked is not None
    assert linked.current_step == STEP_COMPLETED


def test_process_stream_keeps_ledger_visible_on_completion() -> None:
    partial = _STREAM_PARTIAL.read_text()
    start = partial.index("function showCompletion")
    end = partial.index("    function handleEvent", start)
    block = partial[start:end]
    assert "progress.hidden = true" not in block
    assert "if (phaseEl) phaseEl.hidden = true" in block


def test_process_page_summary_above_rows_and_actions_below() -> None:
    html = _PROCESS_TEMPLATE.read_text()
    complete_pos = html.index('id="stream-complete"')
    progress_pos = html.index('id="mode-c-progress"')
    actions_pos = html.index('id="stream-complete-actions"')
    assert complete_pos < progress_pos < actions_pos


def _record_with_outcomes(db, outcomes: list[PROutcome], *, status: str = "completed"):
    record = create_action_record(_HASH, "owner/repo", [o.candidate_id for o in outcomes], db)
    for outcome in outcomes:
        update_pr_outcome(record.action_id, outcome, db)
    finalize_action_record(record.action_id, status, db)
    return load_action_record(record.action_id, db)


def test_results_page_shows_honest_breakdown_clean_run(client: TestClient, wizard_db) -> None:
    record = _record_with_outcomes(
        wizard_db,
        [
            PROutcome(
                "c1",
                "left-pad",
                "1.0.0",
                "1.0.1",
                "patch",
                "opened",
                pr_number=42,
                pr_url="https://github.com/o/r/pull/42",
            )
        ],
    )
    assert record is not None
    with mock.patch.object(dashboard_mod, "load_scan_summary_for_action_page", return_value=None):
        r = client.get(f"/results/{record.action_id}")
    assert r.status_code == 200
    assert "1 PR opened" in r.text
    assert "1 of 1" not in r.text


def test_results_page_shows_split_breakdown_and_already_open_badge(
    client: TestClient, wizard_db
) -> None:
    record = _record_with_outcomes(
        wizard_db,
        [
            PROutcome("c1", "pkg-a", "1", "2", "patch", "opened", pr_number=1),
            PROutcome(
                "c2",
                "pkg-b",
                "1",
                "2",
                "patch",
                "already_exists",
                pr_number=2,
                pr_url="https://github.com/o/r/pull/2",
            ),
            PROutcome("c3", "pkg-c", "1", "2", "patch", "failed", error="boom"),
        ],
        status="partial",
    )
    assert record is not None
    with mock.patch.object(dashboard_mod, "load_scan_summary_for_action_page", return_value=None):
        r = client.get(f"/results/{record.action_id}")
    assert r.status_code == 200
    assert "1 PR opened · 1 already open · 1 failed" in r.text
    assert "Already open" in r.text
    assert "stream-outcome-badge--already-open" in r.text


def test_pr_outcome_row_partial_renders_already_open_badge() -> None:
    outcome = PROutcome(
        "c1",
        "pkg-b",
        "1.0.0",
        "1.0.1",
        "patch",
        "already_exists",
        pr_number=2,
        pr_url="https://github.com/o/r/pull/2",
    )
    html = dashboard_mod.templates.env.get_template("partials/_pr_outcome_row.html").render(
        outcome=outcome
    )
    assert "Already open" in html
    assert "stream-outcome-badge--already-open" in html
    assert 'data-status="already_exists"' in html


def test_counts_from_pr_outcomes_matches_row_statuses() -> None:
    outcomes = [
        PROutcome("c1", "a", "1", "2", "patch", "opened"),
        PROutcome("c2", "b", "1", "2", "patch", "opened"),
        PROutcome("c3", "c", "1", "2", "patch", "already_exists"),
        PROutcome("c4", "d", "1", "2", "patch", "failed"),
        PROutcome("c5", "e", "1", "2", "patch", "skipped"),
    ]
    counts = counts_from_pr_outcomes(outcomes)
    assert counts.opened == sum(1 for o in outcomes if o.status == "opened")
    assert counts.already_exists == sum(1 for o in outcomes if o.status == "already_exists")
    assert counts.failed == sum(1 for o in outcomes if o.status == "failed")
    assert counts.skipped == sum(1 for o in outcomes if o.status == "skipped")
    assert format_completion_breakdown(counts) == "2 PRs opened · 1 already open · 2 failed"
