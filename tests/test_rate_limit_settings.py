"""Rate-limit config knobs (fail-safe parsing) and the day-counter migration."""

from __future__ import annotations

from pathlib import Path

import pytest

from arguss.core.cache import get_connection, init_db
from arguss.settings import Settings, _parse_int_env


def test_parse_int_env_missing_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ARGUSS_TEST_LIMIT", raising=False)
    assert _parse_int_env("ARGUSS_TEST_LIMIT", 60) == 60


def test_parse_int_env_empty_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUSS_TEST_LIMIT", "   ")
    assert _parse_int_env("ARGUSS_TEST_LIMIT", 60) == 60


def test_parse_int_env_invalid_falls_back_not_unlimited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ARGUSS_TEST_LIMIT", "not-a-number")
    assert _parse_int_env("ARGUSS_TEST_LIMIT", 200) == 200


def test_parse_int_env_negative_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUSS_TEST_LIMIT", "-5")
    assert _parse_int_env("ARGUSS_TEST_LIMIT", 20) == 20


def test_parse_int_env_valid_value_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUSS_TEST_LIMIT", "37")
    assert _parse_int_env("ARGUSS_TEST_LIMIT", 60) == 37


def test_rate_limit_knobs_have_conservative_defaults() -> None:
    """Class-level defaults exist and are never unlimited."""
    assert Settings.rate_limit_enabled is True
    assert Settings.rate_limit_ip_per_minute > 0
    assert Settings.rate_limit_scans_per_session > 0
    assert Settings.rate_limit_scans_per_ip_per_hour > 0
    assert Settings.anthropic_daily_ceiling > 0


def test_migration_014_creates_anthropic_daily_usage(tmp_path: Path) -> None:
    conn = get_connection(tmp_path / "test.db")
    init_db(conn)

    columns = {
        row["name"]: row["type"]
        for row in conn.execute("PRAGMA table_info(anthropic_daily_usage)").fetchall()
    }
    assert columns.get("day") == "TEXT"
    assert columns.get("calls") == "INTEGER"

    version_row = conn.execute("SELECT version FROM schema_version WHERE version = 14").fetchone()
    assert version_row is not None
    conn.close()
