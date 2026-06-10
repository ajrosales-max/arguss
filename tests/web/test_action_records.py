"""Unit tests for action_records persistence and SSE mirroring."""

from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path

import pytest

from arguss.web.action_records import (
    PROutcome,
    create_action_record,
    finalize_action_record,
    load_action_record,
    mirror_action_event,
    update_pr_outcome,
)


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
