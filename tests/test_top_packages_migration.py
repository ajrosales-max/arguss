"""Tests for the top_packages schema migration."""

from __future__ import annotations

from pathlib import Path

from arguss.core.cache import get_connection, init_db


def test_migration_004_creates_top_packages_table(tmp_path: Path) -> None:
    conn = get_connection(tmp_path / "test.db")
    init_db(conn)

    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'top_packages'"
    ).fetchone()
    assert row is not None

    columns = {
        r["name"]: r["type"] for r in conn.execute("PRAGMA table_info(top_packages)").fetchall()
    }
    assert columns["rank"] == "INTEGER"
    assert columns["name"] == "TEXT"
    assert columns["historical_advisory_count"] == "INTEGER"
    assert columns["historical_advisory_ids"] == "TEXT"
    assert columns["latest_version"] == "TEXT"
    assert columns["latest_vulnerable"] == "INTEGER"
    assert columns["latest_advisories"] == "TEXT"
    assert columns["swept_at"] == "TEXT"
    assert columns["previously_vulnerable_version"] == "TEXT"
    assert columns["patched_advisory_ids"] == "TEXT"
    assert columns["max_epss"] == "REAL"
    assert columns["is_malware"] == "INTEGER"
    assert columns["previously_vulnerable_advisories"] == "TEXT"
    assert columns["historical_advisory_summaries"] == "TEXT"
    assert columns["last_advisory_date"] == "TEXT"

    version_row = conn.execute("SELECT version FROM schema_version WHERE version = 7").fetchone()
    assert version_row is not None
    version_12 = conn.execute("SELECT version FROM schema_version WHERE version = 12").fetchone()
    assert version_12 is not None


def test_migration_012_leaves_existing_rows_null(tmp_path: Path) -> None:
    """Pre-012 rows keep NULL in the new columns after additive ALTER."""
    conn = get_connection(tmp_path / "pre012.db")
    init_db(conn)
    conn.execute(
        """
        INSERT INTO top_packages (
            rank, name, historical_advisory_count, historical_advisory_ids, swept_at
        ) VALUES (1, 'legacy-pkg', 0, '[]', '2026-06-01T00:00:00Z')
        """
    )
    conn.commit()
    row = conn.execute(
        "SELECT historical_advisory_summaries, last_advisory_date FROM top_packages WHERE name = ?",
        ("legacy-pkg",),
    ).fetchone()
    assert row is not None
    assert row["historical_advisory_summaries"] is None
    assert row["last_advisory_date"] is None
    conn.close()
