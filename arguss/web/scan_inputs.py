"""Persist URL scan inputs for assessment permalink recovery."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from arguss.core.cache import get_connection, init_db

_SCAN_INPUTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_inputs (
    scan_hash  TEXT PRIMARY KEY,
    mode       TEXT NOT NULL,
    url        TEXT NOT NULL,
    ref        TEXT,
    created_at TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class ScanInputs:
    scan_hash: str
    mode: str
    url: str
    ref: str | None
    created_at: datetime


def _ensure_table(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCAN_INPUTS_SCHEMA)
    conn.commit()


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection(db_path)
    init_db(conn)
    _ensure_table(conn)
    return conn


def ensure_table(db_path: Path) -> None:
    conn = _connect(db_path)
    conn.close()


def save_scan_inputs(
    scan_hash: str,
    mode: str,
    url: str,
    ref: str | None,
    db_path: Path,
) -> None:
    """Idempotent. INSERT OR REPLACE - re-running the same scan updates the timestamp."""
    now = datetime.now(UTC).isoformat()
    conn = _connect(db_path)
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO scan_inputs (scan_hash, mode, url, ref, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (scan_hash, mode, url, ref, now),
        )
        conn.commit()
    finally:
        conn.close()


def load_scan_inputs(scan_hash: str, db_path: Path) -> ScanInputs | None:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT scan_hash, mode, url, ref, created_at FROM scan_inputs WHERE scan_hash = ?",
            (scan_hash,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return ScanInputs(
        scan_hash=row["scan_hash"],
        mode=row["mode"],
        url=row["url"],
        ref=row["ref"],
        created_at=datetime.fromisoformat(row["created_at"]),
    )
