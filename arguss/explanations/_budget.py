"""Durable global daily ceiling on Anthropic calls.

This is a CALL-COUNT ceiling, not a token/dollar cap: every reserved call
counts as 1 regardless of prompt size or response length. The counter is a
per-UTC-day row in SQLite (anthropic_daily_usage, migration 014) on the
persistent volume, so it survives process restarts and deploys.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

from arguss.core.cache import get_connection, init_db

_LOG = logging.getLogger(__name__)

# Conditional upsert: insert today's row at 1, or increment it only while
# still under the ceiling. Single statement = atomic check-and-increment;
# two concurrent calls at ceiling-1 cannot both pass.
_RESERVE_SQL = """
INSERT INTO anthropic_daily_usage (day, calls)
VALUES (?, 1)
ON CONFLICT(day) DO UPDATE SET calls = calls + 1
WHERE anthropic_daily_usage.calls < ?
"""


def _utc_day() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def try_reserve_anthropic_call(db_path: Path, *, ceiling: int) -> bool:
    """Atomically reserve one Anthropic call against today's UTC-day ceiling.

    Returns True when the call may proceed (the counter was incremented),
    False when the ceiling is reached. Fails CLOSED: if the counter store is
    unavailable the call is denied rather than becoming silently unlimited.
    """
    if ceiling <= 0:
        return False
    try:
        conn = get_connection(db_path)
        try:
            init_db(conn)
            cur = conn.execute(_RESERVE_SQL, (_utc_day(), ceiling))
            conn.commit()
            return cur.rowcount == 1
        finally:
            conn.close()
    except Exception as exc:
        _LOG.warning("Anthropic budget reserve failed; denying call: %s", exc)
        return False


def anthropic_calls_today(db_path: Path) -> int:
    """Current call count for today's UTC day (0 if no row yet)."""
    conn = get_connection(db_path)
    try:
        init_db(conn)
        row = conn.execute(
            "SELECT calls FROM anthropic_daily_usage WHERE day = ?",
            (_utc_day(),),
        ).fetchone()
        return int(row["calls"]) if row is not None else 0
    finally:
        conn.close()
