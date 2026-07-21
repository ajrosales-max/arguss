"""Unit tests for action_records persistence and SSE mirroring."""

from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path

import pytest

from arguss.web.action_records import (
    PROutcome,
    create_action_record,
    distinct_failure_reasons,
    finalize_action_record,
    load_action_record,
    mirror_action_event,
    update_pr_outcome,
)
from arguss.web.process_hydration import build_process_hydration


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / "actions.db"


def test_create_action_record_generates_uuid_and_persists(db: Path) -> None:
    record = create_action_record("hash1", "o/r", ["c1"], db)
    uuid.UUID(record.action_id)
    loaded = load_action_record(record.action_id, db)
    assert loaded is not None
    assert loaded.scan_hash == "hash1"
    assert loaded.repo_display == "o/r"


def test_create_action_record_initial_status_pending(db: Path) -> None:
    record = create_action_record("hash1", "o/r", [], db)
    assert record.status == "pending"
    loaded = load_action_record(record.action_id, db)
    assert loaded is not None and loaded.status == "pending"
    assert loaded.completed_at is None


def test_update_pr_outcome_creates_when_missing(db: Path) -> None:
    record = create_action_record("hash1", "o/r", [], db)
    update_pr_outcome(
        record.action_id,
        PROutcome(
            candidate_id="c1",
            package="pkg",
            from_version="1.0.0",
            to_version="1.0.1",
            fix_kind="patch",
            status="pending",
        ),
        db,
    )
    loaded = load_action_record(record.action_id, db)
    assert loaded is not None
    assert len(loaded.pr_outcomes) == 1
    assert loaded.pr_outcomes[0].candidate_id == "c1"


def test_update_pr_outcome_updates_existing_status_to_opened(db: Path) -> None:
    record = create_action_record("hash1", "o/r", [], db)
    base = PROutcome("c1", "pkg", "1", "2", "patch", "pending")
    update_pr_outcome(record.action_id, base, db)
    update_pr_outcome(
        record.action_id,
        PROutcome("c1", "pkg", "1", "2", "patch", "opened", pr_number=7, pr_url="https://pr"),
        db,
    )
    loaded = load_action_record(record.action_id, db)
    assert loaded is not None
    assert loaded.pr_outcomes[0].status == "opened"
    assert loaded.pr_outcomes[0].pr_number == 7


def test_update_pr_outcome_records_failure(db: Path) -> None:
    record = create_action_record("hash1", "o/r", [], db)
    update_pr_outcome(
        record.action_id,
        PROutcome("c1", "pkg", "1", "2", "patch", "failed", error="boom"),
        db,
    )
    loaded = load_action_record(record.action_id, db)
    assert loaded is not None
    assert loaded.pr_outcomes[0].error == "boom"


def test_finalize_action_record_sets_status_completed_when_all_opened(db: Path) -> None:
    record = create_action_record("hash1", "o/r", [], db)
    update_pr_outcome(
        record.action_id,
        PROutcome("c1", "pkg", "1", "2", "patch", "opened"),
        db,
    )
    finalize_action_record(record.action_id, "completed", db)
    loaded = load_action_record(record.action_id, db)
    assert loaded is not None
    assert loaded.status == "completed"
    assert loaded.completed_at is not None


def test_finalize_action_record_sets_status_partial_when_some_failed(db: Path) -> None:
    record = create_action_record("hash1", "o/r", [], db)
    finalize_action_record(record.action_id, "partial", db)
    loaded = load_action_record(record.action_id, db)
    assert loaded is not None and loaded.status == "partial"


def test_load_action_record_returns_full_record(db: Path) -> None:
    record = create_action_record("hash1", "o/r", ["a", "b"], db)
    loaded = load_action_record(record.action_id, db)
    assert loaded is not None
    assert loaded.selected_candidate_ids == ["a", "b"]
    assert isinstance(loaded.started_at, datetime)


def test_load_action_record_returns_none_for_unknown_id(db: Path) -> None:
    assert load_action_record(str(uuid.uuid4()), db) is None


def test_mirror_scan_complete_finalizes_partial(db: Path) -> None:
    record = create_action_record("hash1", "o/r", [], db)
    mirror_action_event(
        record.action_id,
        {"type": "scan_complete", "total": 2, "succeeded": 1, "failed": 1, "skipped": 0},
        db,
    )
    loaded = load_action_record(record.action_id, db)
    assert loaded is not None and loaded.status == "partial"


def _failed_outcome(candidate_id: str, error: str, status: str = "failed") -> PROutcome:
    return PROutcome(candidate_id, "pkg", "1", "2", "patch", status, error=error)


def test_distinct_failure_reasons_collapses_identical() -> None:
    outcomes = [
        _failed_outcome("c1", "arguss-bot isn't installed on this repository"),
        _failed_outcome("c2", "arguss-bot isn't installed on this repository"),
    ]
    assert distinct_failure_reasons(outcomes) == ["arguss-bot isn't installed on this repository"]


def test_distinct_failure_reasons_keeps_different_in_order() -> None:
    outcomes = [
        _failed_outcome("c1", "reason A"),
        _failed_outcome("c2", "reason B", status="skipped"),
        _failed_outcome("c3", "reason A"),
    ]
    assert distinct_failure_reasons(outcomes) == ["reason A", "reason B"]


def test_distinct_failure_reasons_ignores_successes_and_empty_errors() -> None:
    outcomes = [
        PROutcome("c1", "pkg", "1", "2", "patch", "opened"),
        _failed_outcome("c2", "  "),
        PROutcome("c3", "pkg", "1", "2", "patch", "failed", error=None),
        _failed_outcome("c4", "boom"),
    ]
    assert distinct_failure_reasons(outcomes) == ["boom"]


def _mirror_all_failed(db: Path, errors: list[str]) -> str:
    record = create_action_record("hash1", "o/r", [], db)
    for idx, error in enumerate(errors):
        mirror_action_event(
            record.action_id,
            {
                "type": "action_completed",
                "candidate_id": f"c{idx}",
                "status": "failed",
                "package": "pkg",
                "from": "1",
                "to": "2",
                "fix_kind": "patch",
                "reason": error,
            },
            db,
        )
    mirror_action_event(
        record.action_id,
        {
            "type": "scan_complete",
            "total": len(errors),
            "succeeded": 0,
            "failed": len(errors),
            "skipped": 0,
        },
        db,
    )
    return record.action_id


def test_mirror_scan_complete_all_failed_persists_deduped_reason(db: Path) -> None:
    not_installed = "arguss-bot isn't installed on this repository"
    action_id = _mirror_all_failed(db, [not_installed, not_installed])
    loaded = load_action_record(action_id, db)
    assert loaded is not None
    assert loaded.status == "failed"
    assert loaded.failure_reason == not_installed


def test_mirror_scan_complete_all_failed_keeps_distinct_reasons(db: Path) -> None:
    action_id = _mirror_all_failed(db, ["reason A", "reason B"])
    loaded = load_action_record(action_id, db)
    assert loaded is not None
    assert loaded.status == "failed"
    assert loaded.failure_reason == "reason A\nreason B"


def test_mirror_scan_complete_partial_does_not_set_failure_reason(db: Path) -> None:
    record = create_action_record("hash1", "o/r", [], db)
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
            "reason": "boom",
        },
        db,
    )
    mirror_action_event(
        record.action_id,
        {"type": "scan_complete", "total": 2, "succeeded": 1, "failed": 1, "skipped": 0},
        db,
    )
    loaded = load_action_record(record.action_id, db)
    assert loaded is not None
    assert loaded.status == "partial"
    assert loaded.failure_reason is None


def test_hydration_carries_derived_failure_reason(db: Path) -> None:
    not_installed = "arguss-bot isn't installed on this repository"
    action_id = _mirror_all_failed(db, [not_installed, not_installed])
    loaded = load_action_record(action_id, db)
    assert loaded is not None
    hydration = build_process_hydration(loaded, None)
    assert hydration["terminal"] is True
    assert hydration["status"] == "failed"
    assert hydration["failure_reason"] == not_installed
    assert [o["error"] for o in hydration["pr_outcomes"]] == [not_installed, not_installed]
