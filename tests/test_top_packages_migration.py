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

    version_row = conn.execute("SELECT version FROM schema_version WHERE version = 4").fetchone()
    assert version_row is not None
