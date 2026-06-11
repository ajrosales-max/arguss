"""Tests for scan_response cache schema versioning."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from arguss.core.cache import Cache, get_connection, init_db
from arguss.core.models import SCAN_RESPONSE_SCHEMA_VERSION
from arguss.explanations.scan_cache import (
    _SCAN_CACHE_SOURCE,
    cache_scan_response,
    get_cached_scan_response,
)


def _sample_scan() -> dict:
    return {
        "entries": [],
        "summary": {"total_findings": 0},
        "scan_meta": {"mode": "A"},
    }


def _db(tmp_path: Path) -> Cache:
    conn = get_connection(tmp_path / "cache.db")
    init_db(conn)
    return Cache(conn)


def test_version_constant_is_a_positive_integer() -> None:
    assert isinstance(SCAN_RESPONSE_SCHEMA_VERSION, int)
    assert SCAN_RESPONSE_SCHEMA_VERSION >= 1


def test_write_stores_current_schema_version(tmp_path: Path) -> None:
    cache = _db(tmp_path)
    key = "hash-write-version"
    cache.set_scan_response(
        key,
        _sample_scan(),
        schema_version=SCAN_RESPONSE_SCHEMA_VERSION,
        source=_SCAN_CACHE_SOURCE,
    )
    row = cache.conn.execute(
        "SELECT scan_response_schema_version FROM api_cache WHERE key = ? AND source = ?",
        (key, _SCAN_CACHE_SOURCE),
    ).fetchone()
    assert row is not None
    assert row["scan_response_schema_version"] == SCAN_RESPONSE_SCHEMA_VERSION


def test_read_returns_response_when_version_matches(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("arguss.explanations.scan_cache.settings.db_path", tmp_path / "cache.db")
    scan = _sample_scan()
    key = cache_scan_response(scan)
    loaded = get_cached_scan_response(key)
    assert loaded == scan


def test_read_returns_none_when_version_mismatches(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("arguss.explanations.scan_cache.settings.db_path", tmp_path / "cache.db")
    cache = _db(tmp_path)
    key = "hash-stale"
    now = datetime.now(UTC)
    expires = now + timedelta(hours=24)
    cache.conn.execute(
        """
        INSERT INTO api_cache
            (key, response_json, source, cached_at, expires_at, scan_response_schema_version)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            key,
            json.dumps(_sample_scan()),
            _SCAN_CACHE_SOURCE,
            now.isoformat(),
            expires.isoformat(),
            SCAN_RESPONSE_SCHEMA_VERSION - 1,
        ),
    )
    cache.conn.commit()
    assert get_cached_scan_response(key) is None


def test_read_deletes_row_when_version_mismatches(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("arguss.explanations.scan_cache.settings.db_path", tmp_path / "cache.db")
    cache = _db(tmp_path)
    key = "hash-delete-stale"
    now = datetime.now(UTC)
    expires = now + timedelta(hours=24)
    cache.conn.execute(
        """
        INSERT INTO api_cache
            (key, response_json, source, cached_at, expires_at, scan_response_schema_version)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            key,
            json.dumps(_sample_scan()),
            _SCAN_CACHE_SOURCE,
            now.isoformat(),
            expires.isoformat(),
            0,
        ),
    )
    cache.conn.commit()
    get_cached_scan_response(key)
    row = cache.conn.execute(
        "SELECT 1 FROM api_cache WHERE key = ? AND source = ?",
        (key, _SCAN_CACHE_SOURCE),
    ).fetchone()
    assert row is None


def test_read_returns_none_when_row_absent_entirely(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("arguss.explanations.scan_cache.settings.db_path", tmp_path / "cache.db")
    _db(tmp_path)
    assert get_cached_scan_response("missing-hash") is None


def test_cache_invalidation_allows_fresh_write_after_stale_miss(
    tmp_path: Path, monkeypatch
) -> None:
    """Stale miss returns None; re-caching with current version restores the hit."""
    monkeypatch.setattr("arguss.explanations.scan_cache.settings.db_path", tmp_path / "cache.db")
    cache = _db(tmp_path)
    key = "hash-recover"
    now = datetime.now(UTC)
    expires = now + timedelta(hours=24)
    stale_scan = {**_sample_scan(), "stale": True}
    cache.conn.execute(
        """
        INSERT INTO api_cache
            (key, response_json, source, cached_at, expires_at, scan_response_schema_version)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            key,
            json.dumps(stale_scan),
            _SCAN_CACHE_SOURCE,
            now.isoformat(),
            expires.isoformat(),
            SCAN_RESPONSE_SCHEMA_VERSION - 1,
        ),
    )
    cache.conn.commit()
    assert get_cached_scan_response(key) is None

    fresh_scan = _sample_scan()
    cache.set_scan_response(
        key,
        fresh_scan,
        schema_version=SCAN_RESPONSE_SCHEMA_VERSION,
        source=_SCAN_CACHE_SOURCE,
    )
    assert get_cached_scan_response(key) == fresh_scan
