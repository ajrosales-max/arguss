"""SQLite-backed wizard session storage, cookies, and route guard."""

from __future__ import annotations

import json
import secrets
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import Request
from fastapi.responses import RedirectResponse
from starlette.responses import Response

from arguss.core.cache import get_connection, init_db
from arguss.settings import settings

WIZARD_SESSION_COOKIE = "arguss_wizard_session"
LAST_SCAN_COOKIE = "arguss_last_scan"
SESSION_TTL = timedelta(hours=1)
LAST_SCAN_TTL = timedelta(days=30)

STEP_ASSESSMENT_VIEWED = "assessment"
STEP_SELECTED = "selected"
STEP_AUTHORIZED = "authorized"
STEP_COMPLETED = "completed"
STEP_AUTHORIZE_FAILED = "authorize_failed"

_WIZARD_SCHEMA = """
CREATE TABLE IF NOT EXISTS wizard_sessions (
    token                  TEXT PRIMARY KEY,
    scan_hash              TEXT NOT NULL,
    current_step           TEXT NOT NULL,
    selected_candidate_ids     TEXT NOT NULL DEFAULT '[]',
    auto_merge_candidate_ids   TEXT NOT NULL DEFAULT '[]',
    action_id                  TEXT,
    created_at             TEXT NOT NULL,
    expires_at             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_wizard_sessions_expires ON wizard_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_wizard_sessions_action_id ON wizard_sessions(action_id);
"""


@dataclass
class WizardSession:
    token: str
    scan_hash: str
    current_step: str
    selected_candidate_ids: list[str] = field(default_factory=list)
    auto_merge_candidate_ids: list[str] = field(default_factory=list)
    action_id: str | None = None
    expires_at: datetime = field(
        default_factory=lambda: datetime.now(UTC) + SESSION_TTL,
    )


def _ensure_wizard_table(conn: sqlite3.Connection) -> None:
    conn.executescript(_WIZARD_SCHEMA)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(wizard_sessions)")}
    if "auto_merge_candidate_ids" not in cols:
        conn.execute(
            "ALTER TABLE wizard_sessions ADD COLUMN auto_merge_candidate_ids "
            "TEXT NOT NULL DEFAULT '[]'"
        )
    conn.commit()


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection(db_path)
    init_db(conn)
    _ensure_wizard_table(conn)
    return conn


def ensure_table(db_path: Path) -> None:
    conn = _connect(db_path)
    conn.close()


def _row_to_session(row: sqlite3.Row) -> WizardSession:
    return WizardSession(
        token=row["token"],
        scan_hash=row["scan_hash"],
        current_step=row["current_step"],
        selected_candidate_ids=json.loads(row["selected_candidate_ids"]),
        auto_merge_candidate_ids=json.loads(row["auto_merge_candidate_ids"]),
        action_id=row["action_id"],
        expires_at=datetime.fromisoformat(row["expires_at"]),
    )


def create_session(scan_hash: str, db_path: Path) -> WizardSession:
    token = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    expires = now + SESSION_TTL
    conn = _connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO wizard_sessions (
                token, scan_hash, current_step, selected_candidate_ids,
                auto_merge_candidate_ids, action_id, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                token,
                scan_hash,
                STEP_ASSESSMENT_VIEWED,
                "[]",
                "[]",
                None,
                now.isoformat(),
                expires.isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return WizardSession(
        token=token,
        scan_hash=scan_hash,
        current_step=STEP_ASSESSMENT_VIEWED,
        selected_candidate_ids=[],
        auto_merge_candidate_ids=[],
        action_id=None,
        expires_at=expires,
    )


def load_session(token: str, db_path: Path) -> WizardSession | None:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM wizard_sessions WHERE token = ?",
            (token,),
        ).fetchone()
        if row is None:
            return None
        session = _row_to_session(row)
        if session.expires_at <= datetime.now(UTC):
            return None
        return session
    finally:
        conn.close()


def update_step(token: str, new_step: str, db_path: Path) -> None:
    conn = _connect(db_path)
    try:
        conn.execute(
            "UPDATE wizard_sessions SET current_step = ? WHERE token = ?",
            (new_step, token),
        )
        conn.commit()
    finally:
        conn.close()


def set_selection(
    token: str,
    ids: list[str],
    auto_merge_ids: list[str],
    db_path: Path,
) -> None:
    conn = _connect(db_path)
    try:
        conn.execute(
            """
            UPDATE wizard_sessions
            SET selected_candidate_ids = ?, auto_merge_candidate_ids = ?
            WHERE token = ?
            """,
            (json.dumps(ids), json.dumps(auto_merge_ids), token),
        )
        conn.commit()
    finally:
        conn.close()


def set_action_id(token: str, action_id: str, db_path: Path) -> None:
    conn = _connect(db_path)
    try:
        conn.execute(
            "UPDATE wizard_sessions SET action_id = ? WHERE token = ?",
            (action_id, token),
        )
        conn.commit()
    finally:
        conn.close()


def delete_session(token: str, db_path: Path) -> None:
    conn = _connect(db_path)
    try:
        conn.execute("DELETE FROM wizard_sessions WHERE token = ?", (token,))
        conn.commit()
    finally:
        conn.close()


def prune_expired_sessions(db_path: Path) -> int:
    conn = _connect(db_path)
    try:
        cur = conn.execute(
            "DELETE FROM wizard_sessions WHERE expires_at <= ?",
            (datetime.now(UTC).isoformat(),),
        )
        conn.commit()
        return cur.rowcount or 0
    finally:
        conn.close()


def _cookie_secure() -> bool:
    return settings.is_production


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        WIZARD_SESSION_COOKIE,
        token,
        max_age=int(SESSION_TTL.total_seconds()),
        httponly=True,
        samesite="lax",
        secure=_cookie_secure(),
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(WIZARD_SESSION_COOKIE, path="/")


def set_last_scan_cookie(response: Response, scan_hash: str) -> None:
    response.set_cookie(
        LAST_SCAN_COOKIE,
        scan_hash,
        max_age=int(LAST_SCAN_TTL.total_seconds()),
        httponly=True,
        samesite="lax",
        secure=_cookie_secure(),
        path="/",
    )


def find_session_by_action_id(action_id: str, db_path: Path) -> WizardSession | None:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM wizard_sessions WHERE action_id = ?",
            (action_id,),
        ).fetchone()
        if row is None:
            return None
        session = _row_to_session(row)
        if session.expires_at <= datetime.now(UTC):
            return None
        return session
    finally:
        conn.close()


def transition_session_for_action_outcome(
    action_id: str,
    terminal_step: str,
    db_path: Path,
) -> None:
    session = find_session_by_action_id(action_id, db_path)
    if session is None:
        return
    update_step(session.token, terminal_step, db_path)


def expired_wizard_redirect(request: Request) -> RedirectResponse:
    return _expired_redirect(request)


def _expired_redirect(request: Request) -> RedirectResponse:
    last = request.cookies.get(LAST_SCAN_COOKIE)
    if last:
        return RedirectResponse(
            f"/assessment/{last}?wizard_note=expired",
            status_code=303,
        )
    return RedirectResponse("/scan?wizard_note=expired", status_code=303)


def get_or_redirect_wizard_session(
    request: Request,
    *,
    allowed_steps: Iterable[str],
    db_path: Path,
) -> WizardSession | RedirectResponse:
    token = request.cookies.get(WIZARD_SESSION_COOKIE)
    if not token:
        return _expired_redirect(request)
    session = load_session(token, db_path)
    if session is None:
        return _expired_redirect(request)
    if session.current_step not in set(allowed_steps):
        return _expired_redirect(request)
    return session
