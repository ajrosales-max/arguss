"""Tests for action_run schema migration 008."""

from __future__ import annotations

from pathlib import Path

from arguss.core.cache import get_connection, init_db


def test_migration_008_creates_action_run_tables(tmp_path: Path) -> None:
    conn = get_connection(tmp_path / "test.db")
    init_db(conn)

    run_row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'action_run'"
    ).fetchone()
    assert run_row is not None

    candidate_row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'action_run_candidate'"
    ).fetchone()
    assert candidate_row is not None

    run_columns = {
        r["name"]: r["type"] for r in conn.execute("PRAGMA table_info(action_run)").fetchall()
    }
    assert run_columns["id"] == "TEXT"
    assert run_columns["scan_hash"] == "TEXT"
    assert run_columns["scan_ref"] == "TEXT"
    assert run_columns["mode"] == "TEXT"
    assert run_columns["created_at"] == "TEXT"
    assert run_columns["state"] == "TEXT"
    assert run_columns["wizard_action_id"] == "TEXT"

    candidate_columns = {
        r["name"]: r["type"]
        for r in conn.execute("PRAGMA table_info(action_run_candidate)").fetchall()
    }
    assert candidate_columns["id"] == "TEXT"
    assert candidate_columns["action_run_id"] == "TEXT"
    assert candidate_columns["candidate_id"] == "TEXT"
    assert candidate_columns["package"] == "TEXT"
    assert candidate_columns["from_version"] == "TEXT"
    assert candidate_columns["to_version"] == "TEXT"
    assert candidate_columns["pr_number"] == "INTEGER"
    assert candidate_columns["head_sha"] == "TEXT"
    assert candidate_columns["state"] == "TEXT"
    assert candidate_columns["state_detail"] == "TEXT"
    assert candidate_columns["merge_authorization"] == "TEXT"
    assert candidate_columns["updated_at"] == "TEXT"

    version_row = conn.execute("SELECT version FROM schema_version WHERE version = 8").fetchone()
    assert version_row is not None
