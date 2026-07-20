"""Tests for action_run schema migrations 008 and 013."""

from __future__ import annotations

from pathlib import Path

from arguss.core.cache import get_connection, init_db
from arguss.web.action_runs import create_action_run, load_action_run


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
    assert run_columns["installation_id"] == "TEXT"

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
    assert candidate_columns["engine_score"] == "INTEGER"
    assert candidate_columns["veto_signals"] == "TEXT"
    assert candidate_columns["pr_authorization_appended"] == "INTEGER"

    version_row = conn.execute("SELECT version FROM schema_version WHERE version = 8").fetchone()
    assert version_row is not None

    version_11 = conn.execute("SELECT version FROM schema_version WHERE version = 11").fetchone()
    assert version_11 is not None

    version_13 = conn.execute("SELECT version FROM schema_version WHERE version = 13").fetchone()
    assert version_13 is not None


def test_migration_013_leaves_existing_rows_null(tmp_path: Path) -> None:
    """Pre-013-shaped inserts keep installation_id NULL after additive ALTER."""
    db_path = tmp_path / "pre013.db"
    conn = get_connection(db_path)
    init_db(conn)
    conn.execute(
        """
        INSERT INTO action_run (
            id, scan_hash, scan_ref, mode, created_at, state, wizard_action_id
        ) VALUES (
            'legacy-run', 'hash', 'main', 'C', '2026-07-01T00:00:00+00:00', 'running', NULL
        )
        """
    )
    conn.commit()
    conn.close()

    loaded = load_action_run("legacy-run", db_path)
    assert loaded is not None
    assert loaded.installation_id is None


def test_create_action_run_installation_id_round_trip(tmp_path: Path) -> None:
    db_path = tmp_path / "roundtrip.db"

    with_id = create_action_run(
        "hash-with-id",
        "C",
        db_path,
        installation_id="12345678",
    )
    without_id = create_action_run("hash-without-id", "C", db_path)

    assert with_id.installation_id == "12345678"
    assert without_id.installation_id is None

    reloaded_with = load_action_run(with_id.id, db_path)
    reloaded_without = load_action_run(without_id.id, db_path)
    assert reloaded_with is not None
    assert reloaded_without is not None
    assert reloaded_with.installation_id == "12345678"
    assert reloaded_without.installation_id is None
