"""Tests for SQLite wizard session infrastructure."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.responses import RedirectResponse
from starlette.requests import Request
from starlette.responses import Response

from arguss.core.cache import get_connection
from arguss.web.wizard_session import (
    LAST_SCAN_COOKIE,
    LAST_SCAN_TTL,
    SESSION_TTL,
    STEP_ASSESSMENT_VIEWED,
    STEP_AUTHORIZED,
    STEP_SELECTED,
    WIZARD_SESSION_COOKIE,
    WizardSession,
    create_session,
    delete_session,
    ensure_table,
    get_or_redirect_wizard_session,
    load_session,
    prune_expired_sessions,
    set_action_id,
    set_last_scan_cookie,
    set_selection,
    set_session_cookie,
    update_step,
)


def _request(cookies: dict[str, str] | None = None) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if cookies:
        raw = "; ".join(f"{k}={v}" for k, v in cookies.items())
        headers.append((b"cookie", raw.encode("latin-1")))
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": headers,
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
    }
    return Request(scope)


def test_ensure_table_idempotent(tmp_path) -> None:
    db = tmp_path / "wizard.db"
    ensure_table(db)
    ensure_table(db)
    conn = get_connection(db)
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='wizard_sessions'"
    ).fetchone()
    conn.close()
    assert row is not None


def test_create_session_generates_unique_token(tmp_path) -> None:
    db = tmp_path / "wizard.db"
    a = create_session("hash-a", db)
    b = create_session("hash-b", db)
    assert a.token
    assert b.token
    assert a.token != b.token


def test_create_session_persists_with_correct_initial_step(tmp_path) -> None:
    db = tmp_path / "wizard.db"
    session = create_session("scan-123", db)
    loaded = load_session(session.token, db)
    assert loaded is not None
    assert loaded.scan_hash == "scan-123"
    assert loaded.current_step == STEP_ASSESSMENT_VIEWED
    assert loaded.selected_candidate_ids == []


def test_load_session_returns_session_when_valid(tmp_path) -> None:
    db = tmp_path / "wizard.db"
    session = create_session("scan-abc", db)
    loaded = load_session(session.token, db)
    assert isinstance(loaded, WizardSession)
    assert loaded.token == session.token


def test_load_session_returns_none_when_expired(tmp_path) -> None:
    db = tmp_path / "wizard.db"
    session = create_session("scan-exp", db)
    conn = get_connection(db)
    past = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
    conn.execute(
        "UPDATE wizard_sessions SET expires_at = ? WHERE token = ?",
        (past, session.token),
    )
    conn.commit()
    conn.close()
    assert load_session(session.token, db) is None


def test_load_session_returns_none_for_unknown_token(tmp_path) -> None:
    db = tmp_path / "wizard.db"
    ensure_table(db)
    assert load_session("missing-token", db) is None


def test_update_step_persists(tmp_path) -> None:
    db = tmp_path / "wizard.db"
    session = create_session("scan-step", db)
    update_step(session.token, STEP_SELECTED, db)
    loaded = load_session(session.token, db)
    assert loaded is not None
    assert loaded.current_step == STEP_SELECTED


def test_set_selection_persists_as_json(tmp_path) -> None:
    db = tmp_path / "wizard.db"
    session = create_session("scan-sel", db)
    ids = ["cand-a-001", "cand-b-002"]
    set_selection(session.token, ids, db)
    loaded = load_session(session.token, db)
    assert loaded is not None
    assert loaded.selected_candidate_ids == ids


def test_set_action_id_persists(tmp_path) -> None:
    db = tmp_path / "wizard.db"
    session = create_session("scan-act", db)
    set_action_id(session.token, "scan-run-99", db)
    loaded = load_session(session.token, db)
    assert loaded is not None
    assert loaded.action_id == "scan-run-99"


def test_delete_session_removes_row(tmp_path) -> None:
    db = tmp_path / "wizard.db"
    session = create_session("scan-del", db)
    delete_session(session.token, db)
    assert load_session(session.token, db) is None


def test_prune_expired_sessions_removes_only_expired(tmp_path) -> None:
    db = tmp_path / "wizard.db"
    live = create_session("live", db)
    expired = create_session("expired", db)
    conn = get_connection(db)
    past = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    conn.execute(
        "UPDATE wizard_sessions SET expires_at = ? WHERE token = ?",
        (past, expired.token),
    )
    conn.commit()
    conn.close()
    removed = prune_expired_sessions(db)
    assert removed == 1
    assert load_session(live.token, db) is not None
    assert load_session(expired.token, db) is None


def test_get_or_redirect_returns_session_when_step_allowed(tmp_path) -> None:
    db = tmp_path / "wizard.db"
    session = create_session("scan-guard", db)
    update_step(session.token, STEP_SELECTED, db)
    result = get_or_redirect_wizard_session(
        _request({WIZARD_SESSION_COOKIE: session.token}),
        allowed_steps=[STEP_SELECTED],
        db_path=db,
    )
    assert isinstance(result, WizardSession)
    assert result.token == session.token


def test_get_or_redirect_returns_redirect_when_no_cookie(tmp_path) -> None:
    db = tmp_path / "wizard.db"
    result = get_or_redirect_wizard_session(
        _request(),
        allowed_steps=[STEP_SELECTED],
        db_path=db,
    )
    assert isinstance(result, RedirectResponse)
    assert result.status_code == 303
    assert result.headers["location"] == "/scan?wizard_note=expired"


def test_get_or_redirect_returns_redirect_when_step_disallowed(tmp_path) -> None:
    db = tmp_path / "wizard.db"
    session = create_session("scan-wrong-step", db)
    result = get_or_redirect_wizard_session(
        _request({WIZARD_SESSION_COOKIE: session.token}),
        allowed_steps=[STEP_AUTHORIZED],
        db_path=db,
    )
    assert isinstance(result, RedirectResponse)


def test_get_or_redirect_returns_redirect_when_session_expired(tmp_path) -> None:
    db = tmp_path / "wizard.db"
    session = create_session("scan-expired-guard", db)
    conn = get_connection(db)
    past = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    conn.execute(
        "UPDATE wizard_sessions SET expires_at = ? WHERE token = ?",
        (past, session.token),
    )
    conn.commit()
    conn.close()
    result = get_or_redirect_wizard_session(
        _request({WIZARD_SESSION_COOKIE: session.token}),
        allowed_steps=[STEP_ASSESSMENT_VIEWED],
        db_path=db,
    )
    assert isinstance(result, RedirectResponse)


def test_expired_redirect_uses_last_scan_cookie_when_present(tmp_path) -> None:
    db = tmp_path / "wizard.db"
    result = get_or_redirect_wizard_session(
        _request({LAST_SCAN_COOKIE: "last-hash-xyz"}),
        allowed_steps=[STEP_SELECTED],
        db_path=db,
    )
    assert isinstance(result, RedirectResponse)
    assert result.headers["location"] == "/assessment/last-hash-xyz?wizard_note=expired"


def test_expired_redirect_falls_back_to_scan_when_no_last_scan(tmp_path) -> None:
    db = tmp_path / "wizard.db"
    result = get_or_redirect_wizard_session(
        _request(),
        allowed_steps=[STEP_SELECTED],
        db_path=db,
    )
    assert isinstance(result, RedirectResponse)
    assert result.headers["location"] == "/scan?wizard_note=expired"


def test_set_session_cookie_httponly_and_lax() -> None:
    response = Response()
    set_session_cookie(response, "tok-abc")
    cookie = response.headers.get("set-cookie", "")
    assert "HttpOnly" in cookie
    assert "samesite=lax" in cookie.lower()
    assert f"Max-Age={int(SESSION_TTL.total_seconds())}" in cookie


def test_set_last_scan_cookie_30_day_max_age() -> None:
    response = Response()
    set_last_scan_cookie(response, "scan-hash-1")
    cookie = response.headers.get("set-cookie", "")
    assert f"Max-Age={int(LAST_SCAN_TTL.total_seconds())}" in cookie
    assert LAST_SCAN_COOKIE in cookie
