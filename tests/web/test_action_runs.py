"""Unit tests for action_runs registry."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from arguss.web.action_runs import (
    TERMINAL_CANDIDATE_STATES,
    action_run_to_dict,
    add_action_run_candidate,
    candidate_to_dict,
    create_action_run,
    finalize_action_run_if_terminal,
    is_action_run_terminal,
    load_action_run,
    load_action_run_by_wizard_action_id,
    mark_action_run_completed,
    update_action_run_candidate,
)


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / "action_runs.db"


def _assert_no_secrets(value: object) -> None:
    blob = json.dumps(value).lower()
    assert "pat" not in blob
    assert "token" not in blob
    assert "bearer" not in blob


def test_create_and_load_action_run(db: Path) -> None:
    run = create_action_run("scan-hash", "mode_c", db, scan_ref="main")
    uuid.UUID(run.id)
    assert run.state == "running"
    loaded = load_action_run(run.id, db)
    assert loaded is not None
    assert loaded.scan_hash == "scan-hash"
    assert loaded.scan_ref == "main"
    assert loaded.mode == "mode_c"
    assert loaded.candidates == []


def test_wizard_action_id_link(db: Path) -> None:
    wizard_id = str(uuid.uuid4())
    run = create_action_run("h", "mode_c", db, wizard_action_id=wizard_id)
    by_wizard = load_action_run_by_wizard_action_id(wizard_id, db)
    assert by_wizard is not None
    assert by_wizard.id == run.id
    assert by_wizard.wizard_action_id == wizard_id


def test_add_and_update_candidate_states(db: Path) -> None:
    run = create_action_run("h", "mode_c", db)
    cand = add_action_run_candidate(
        run.id, "c1", "pkg", "1.0.0", "1.0.1", db, pr_number=42, head_sha="abc123"
    )
    assert cand.state == "pr_opened"
    assert cand.merge_authorization == "engine"
    updated = update_action_run_candidate(
        cand.id, db, state="ci_running", merge_authorization="human_override"
    )
    assert updated is not None
    assert updated.state == "ci_running"
    assert updated.merge_authorization == "human_override"
    loaded = load_action_run(run.id, db)
    assert loaded is not None
    assert len(loaded.candidates) == 1
    assert loaded.candidates[0].pr_number == 42
    assert loaded.candidates[0].head_sha == "abc123"


def test_terminal_detection_and_finalize(db: Path) -> None:
    run = create_action_run("h", "mode_c", db)
    assert not is_action_run_terminal(run)
    cand = add_action_run_candidate(run.id, "c1", "pkg", "1", "2", db)
    loaded = load_action_run(run.id, db)
    assert loaded is not None
    assert not is_action_run_terminal(loaded)
    assert not finalize_action_run_if_terminal(run.id, db)
    update_action_run_candidate(cand.id, db, state="merged")
    loaded = load_action_run(run.id, db)
    assert loaded is not None
    assert is_action_run_terminal(loaded)
    assert finalize_action_run_if_terminal(run.id, db)
    finalized = load_action_run(run.id, db)
    assert finalized is not None
    assert finalized.state == "completed"


def test_terminal_candidate_states_cover_expected_set() -> None:
    expected = {
        "merged",
        "ci_failed",
        "no_checks",
        "sha_conflict",
        "timed_out",
        "killed",
        "head_sha_unresolved",
    }
    assert expected == TERMINAL_CANDIDATE_STATES


def test_serialized_dicts_exclude_secrets(db: Path) -> None:
    run = create_action_run("h", "mode_c", db, wizard_action_id=str(uuid.uuid4()))
    cand = add_action_run_candidate(
        run.id,
        "c1",
        "pkg",
        "1",
        "2",
        db,
        state_detail="ci pending",
    )
    loaded = load_action_run(run.id, db)
    assert loaded is not None
    _assert_no_secrets(candidate_to_dict(cand))
    _assert_no_secrets(action_run_to_dict(loaded))
    assert candidate_to_dict(cand)["merge_authorization"] == "engine"


def test_update_candidate_unknown_id_returns_none(db: Path) -> None:
    assert update_action_run_candidate(str(uuid.uuid4()), db, state="merged") is None


def test_lazy_reconciliation_stale_running_run(db: Path, monkeypatch) -> None:
    from datetime import UTC, datetime, timedelta

    import arguss.web.action_runs as ar

    monkeypatch.setattr(ar.settings, "mode_c_merge_wait_cap_seconds", 60)
    run = create_action_run("h", "mode_c", db)
    cand = add_action_run_candidate(run.id, "c1", "pkg", "1.0.0", "1.0.1", db, state="ci_running")
    conn = ar._connect(db)
    try:
        stale = (datetime.now(UTC) - timedelta(seconds=400)).isoformat()
        conn.execute("UPDATE action_run SET created_at = ? WHERE id = ?", (stale, run.id))
        conn.commit()
    finally:
        conn.close()

    loaded = load_action_run(run.id, db)
    assert loaded is not None
    assert loaded.state == "completed"
    assert loaded.candidates[0].state == "timed_out"
    assert loaded.candidates[0].state_detail == "merge wait interrupted or exceeded"
    assert cand.id == loaded.candidates[0].id


def test_candidate_state_badge_class_maps_states() -> None:
    from arguss.web.action_runs import candidate_state_badge_class

    assert candidate_state_badge_class("merged") == "merge-status--merged"
    assert candidate_state_badge_class("ci_running") == "merge-status--running"


def test_action_run_to_dict_includes_terminal(db: Path) -> None:
    run = create_action_run("h", "mode_c", db)
    loaded = load_action_run(run.id, db)
    assert loaded is not None
    d = action_run_to_dict(loaded)
    assert d["terminal"] is False
    mark_action_run_completed(run.id, db)
    loaded2 = load_action_run(run.id, db)
    assert loaded2 is not None
    assert action_run_to_dict(loaded2)["terminal"] is True
