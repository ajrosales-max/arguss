"""SQLite cache and migrations for Arguss.

WAL mode is enabled for better concurrent read performance.
Migrations are numbered SQL files in arguss/core/migrations/; they're applied
automatically at startup based on the schema_version table.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def get_connection(db_path: Path | str) -> sqlite3.Connection:
    """Open a SQLite connection with sensible defaults for this project."""
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Apply any pending schema migrations.

    Tracks applied migrations in the schema_version table. Migration files
    are SQL files in MIGRATIONS_DIR named like '001_initial.sql'.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
        """
    )
    conn.commit()

    current_row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    current = current_row[0] if current_row and current_row[0] is not None else 0

    for sql_file in sorted(MIGRATIONS_DIR.glob("*.sql")):
        version = int(sql_file.stem.split("_")[0])
        if version > current:
            conn.executescript(sql_file.read_text())
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (version, datetime.now(UTC).isoformat()),
            )
            conn.commit()


class Cache:
    """Cache layer wrapping the SQLite database.

    Handles API response caching with TTL eviction. AI explanation caching
    lands in Week 10 as separate methods.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def get_api_response(self, source: str, key: str) -> dict[str, Any] | None:
        """Retrieve a cached API response, or None if missing/expired."""
        row = self.conn.execute(
            """
            SELECT response_json FROM api_cache
            WHERE key = ? AND source = ? AND expires_at > ?
            """,
            (key, source, datetime.now(UTC).isoformat()),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["response_json"])  # type: ignore[no-any-return]

    def set_api_response(
        self,
        source: str,
        key: str,
        response: dict[str, Any],
        ttl_hours: int = 24,
    ) -> None:
        """Store an API response with a TTL."""
        now = datetime.now(UTC)
        expires = now + timedelta(hours=ttl_hours)
        self.conn.execute(
            """
            INSERT OR REPLACE INTO api_cache
                (key, response_json, source, cached_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (key, json.dumps(response), source, now.isoformat(), expires.isoformat()),
        )
        self.conn.commit()

    def get_cached_text(self, source: str, key: str) -> str | None:
        """Retrieve cached plain text, or None if missing/expired."""
        row = self.conn.execute(
            """
            SELECT response_json FROM api_cache
            WHERE key = ? AND source = ? AND expires_at > ?
            """,
            (key, source, datetime.now(UTC).isoformat()),
        ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["response_json"])
        text = payload.get("text")
        return text if isinstance(text, str) else None

    def set_cached_text(
        self,
        source: str,
        key: str,
        text: str,
        *,
        ttl_seconds: int = 86400,
    ) -> None:
        """Store plain text with a TTL (default 24 hours)."""
        now = datetime.now(UTC)
        expires = now + timedelta(seconds=ttl_seconds)
        self.conn.execute(
            """
            INSERT OR REPLACE INTO api_cache
                (key, response_json, source, cached_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                key,
                json.dumps({"text": text}),
                source,
                now.isoformat(),
                expires.isoformat(),
            ),
        )
        self.conn.commit()

    def cleanup_expired(self) -> int:
        """Remove expired entries from all caches. Returns count removed."""
        now = datetime.now(UTC).isoformat()
        cur1 = self.conn.execute("DELETE FROM api_cache WHERE expires_at <= ?", (now,))
        cur2 = self.conn.execute("DELETE FROM ai_explanations WHERE expires_at <= ?", (now,))
        self.conn.commit()
        return (cur1.rowcount or 0) + (cur2.rowcount or 0)
