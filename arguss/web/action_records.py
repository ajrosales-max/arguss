"""SQLite-backed action records for Mode C remediation permalinks."""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from arguss.core.cache import get_connection, init_db
from arguss.explanations.scan_cache import get_cached_scan_response
from arguss.web.wizard_session import (
    STEP_AUTHORIZE_FAILED,
    STEP_COMPLETED,
    transition_session_for_action_outcome,
)

_LOG = logging.getLogger(__name__)

_ACTION_SCHEMA = """
CREATE TABLE IF NOT EXISTS action_records (
    action_id              TEXT PRIMARY KEY,
    scan_hash              TEXT NOT NULL,
    repo_display           TEXT NOT NULL,
    status                 TEXT NOT NULL,
    started_at             TEXT NOT NULL,
    completed_at           TEXT,
    selected_candidate_ids TEXT NOT NULL,
    pr_outcomes            TEXT NOT NULL DEFAULT '[]',
    failure_reason         TEXT,
    auto_merge_after_ci        INTEGER NOT NULL DEFAULT 1,
    auto_merge_candidate_ids   TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_action_records_scan_hash ON action_records(scan_hash);
"""


@dataclass
class PROutcome:
    candidate_id: str
    package: str
    from_version: str
    to_version: str
    fix_kind: str
    status: str
    pr_number: int | None = None
    pr_url: str | None = None
    error: str | None = None


@dataclass
class ActionRecord:
    action_id: str
    scan_hash: str
    repo_display: str
    status: str
    started_at: datetime
    completed_at: datetime | None
    selected_candidate_ids: list[str]
    pr_outcomes: list[PROutcome] = field(default_factory=list)
    failure_reason: str | None = None
    auto_merge_after_ci: bool = True
    auto_merge_candidate_ids: list[str] = field(default_factory=list)


def load_scan_summary_for_action_page(scan_hash: str) -> dict[str, Any] | None:
    cached = get_cached_scan_response(scan_hash)
    if cached is None:
        return None
    summary = cached.get("summary") or {}
    project_scores = cached.get("project_scores") or {}
    scan_meta = cached.get("scan_meta") or {}
    return {
        "repo_display": scan_meta.get("repo_display"),
        "ref": scan_meta.get("ref", "HEAD"),
        "risk_score": project_scores.get("prs"),
        "findings_total": summary.get("total_findings"),
        "candidate_total": summary.get("total_candidates"),
    }


def _finalize_status_from_scan_complete(event: dict[str, Any]) -> str:
    total = int(event.get("total") or 0)
    succeeded = int(event.get("succeeded") or 0) + int(event.get("already_exists") or 0)
    failed = int(event.get("failed") or 0) + int(event.get("skipped") or 0)
    if total == 0:
        return "completed"
    if succeeded >= total:
        return "completed"
    if succeeded == 0 and failed > 0:
        return "failed"
    if failed > 0:
        return "partial"
    return "completed"


def distinct_failure_reasons(outcomes: list[PROutcome]) -> list[str]:
    """Deduplicated error strings from failed/skipped outcomes, first-seen order.

    Identical reasons (e.g. every candidate hit the same not-installed 403)
    collapse to one entry; genuinely different reasons all survive.
    """
    seen: set[str] = set()
    reasons: list[str] = []
    for outcome in outcomes:
        if outcome.status not in ("failed", "skipped"):
            continue
        reason = (outcome.error or "").strip()
        if not reason or reason in seen:
            continue
        seen.add(reason)
        reasons.append(reason)
    return reasons


def _outcome_from_planned_candidate(candidate: dict[str, Any]) -> PROutcome:
    return PROutcome(
        candidate_id=str(candidate["candidate_id"]),
        package=str(candidate.get("package", "")),
        from_version=str(candidate.get("from", "")),
        to_version=str(candidate.get("to", "")),
        fix_kind=str(candidate.get("fix_kind", "")),
        status="pending",
    )


def _outcome_from_started(event: dict[str, Any]) -> PROutcome:
    return PROutcome(
        candidate_id=str(event["candidate_id"]),
        package=str(event.get("package", "")),
        from_version=str(event.get("from", "")),
        to_version=str(event.get("to", "")),
        fix_kind=str(event.get("fix_kind", "")),
        status="pending",
    )


def _outcome_from_completed(event: dict[str, Any]) -> PROutcome:
    raw_status = str(event.get("status", "failed"))
    if raw_status == "opened":
        pr_status = "opened"
        error = None
    elif raw_status == "already_exists":
        pr_status = "already_exists"
        error = None
    elif raw_status == "skipped":
        pr_status = "skipped"
        error = event.get("reason")
    else:
        pr_status = "failed"
        error = event.get("reason")
    return PROutcome(
        candidate_id=str(event["candidate_id"]),
        package=str(event.get("package", "")),
        from_version=str(event.get("from", "")),
        to_version=str(event.get("to", "")),
        fix_kind=str(event.get("fix_kind", "")),
        status=pr_status,
        pr_number=event.get("pr_number"),
        pr_url=event.get("pr_url"),
        error=error if isinstance(error, str) else (str(error) if error else None),
    )


def mirror_action_event(action_id: str, event: dict[str, Any], db_path: Path) -> None:
    event_type = event.get("type")
    if event_type == "actions_planned":
        for candidate in event.get("candidates") or []:
            update_pr_outcome(action_id, _outcome_from_planned_candidate(candidate), db_path)
    elif event_type == "action_started":
        if "candidate_id" in event:
            update_pr_outcome(action_id, _outcome_from_started(event), db_path)
    elif event_type == "action_completed":
        if "candidate_id" in event:
            update_pr_outcome(action_id, _outcome_from_completed(event), db_path)
    elif event_type == "scan_complete":
        # scan_complete always moves the wizard session to completed, even when
        # individual PRs failed: the action ran to completion with mixed results.
        # authorize_failed (scan_failed) is reserved for the action failing to run.
        resolved_status = _finalize_status_from_scan_complete(event)
        failure_reason: str | None = None
        if resolved_status == "failed":
            # All candidates failed: derive the run-level reason from the
            # per-candidate errors already mirrored to this record, so the
            # failed process/results pages can show the real cause.
            record = load_action_record(action_id, db_path)
            if record is not None:
                reasons = distinct_failure_reasons(record.pr_outcomes)
                if reasons:
                    failure_reason = "\n".join(reasons)
        finalize_action_record(
            action_id,
            resolved_status,
            db_path,
            failure_reason=failure_reason,
        )
        transition_session_for_action_outcome(action_id, STEP_COMPLETED, db_path)
    elif event_type == "scan_failed":
        reason = event.get("reason")
        failure_reason = reason if isinstance(reason, str) and reason.strip() else None
        finalize_action_record(action_id, "failed", db_path, failure_reason=failure_reason)
        transition_session_for_action_outcome(action_id, STEP_AUTHORIZE_FAILED, db_path)


def form_checkbox_enabled(value: str | None) -> bool:
    """True when an HTML checkbox field was checked (present in form POST)."""
    return value is not None


def create_action_record(
    scan_hash: str,
    repo_display: str,
    selected_candidate_ids: list[str],
    db_path: Path,
    *,
    auto_merge_candidate_ids: list[str] | None = None,
) -> ActionRecord:
    action_id = str(uuid.uuid4())
    now = datetime.now(UTC)
    merge_ids = list(auto_merge_candidate_ids or [])
    conn = _connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO action_records (
                action_id, scan_hash, repo_display, status, started_at,
                completed_at, selected_candidate_ids, pr_outcomes,
                auto_merge_after_ci, auto_merge_candidate_ids
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                action_id,
                scan_hash,
                repo_display,
                "pending",
                now.isoformat(),
                None,
                json.dumps(selected_candidate_ids),
                "[]",
                1 if merge_ids else 0,
                json.dumps(merge_ids),
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return ActionRecord(
        action_id=action_id,
        scan_hash=scan_hash,
        repo_display=repo_display,
        status="pending",
        started_at=now,
        completed_at=None,
        selected_candidate_ids=list(selected_candidate_ids),
        pr_outcomes=[],
        auto_merge_candidate_ids=merge_ids,
    )


def update_pr_outcome(action_id: str, outcome: PROutcome, db_path: Path) -> None:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT pr_outcomes FROM action_records WHERE action_id = ?",
            (action_id,),
        ).fetchone()
        if row is None:
            return
        outcomes = [_outcome_from_dict(item) for item in json.loads(row["pr_outcomes"])]
        replaced = False
        for idx, existing in enumerate(outcomes):
            if existing.candidate_id == outcome.candidate_id:
                merged = PROutcome(
                    candidate_id=outcome.candidate_id,
                    package=outcome.package or existing.package,
                    from_version=outcome.from_version or existing.from_version,
                    to_version=outcome.to_version or existing.to_version,
                    fix_kind=outcome.fix_kind or existing.fix_kind,
                    status=outcome.status or existing.status,
                    pr_number=(
                        outcome.pr_number if outcome.pr_number is not None else existing.pr_number
                    ),
                    pr_url=outcome.pr_url if outcome.pr_url is not None else existing.pr_url,
                    error=outcome.error if outcome.error is not None else existing.error,
                )
                outcomes[idx] = merged
                replaced = True
                break
        if not replaced:
            outcomes.append(outcome)
        _persist_pr_outcomes(conn, action_id, outcomes)
    finally:
        conn.close()


def update_action_record_scan_hash(
    action_id: str,
    scan_hash: str,
    db_path: Path,
) -> None:
    """Point the wizard action record at the Mode C assessment hash (includes action_run_id)."""
    conn = _connect(db_path)
    try:
        conn.execute(
            "UPDATE action_records SET scan_hash = ? WHERE action_id = ?",
            (scan_hash, action_id),
        )
        conn.commit()
    finally:
        conn.close()


def finalize_action_record(
    action_id: str,
    status: str,
    db_path: Path,
    *,
    failure_reason: str | None = None,
) -> None:
    now = datetime.now(UTC).isoformat()
    conn = _connect(db_path)
    try:
        conn.execute(
            """
            UPDATE action_records
            SET status = ?, completed_at = ?, failure_reason = COALESCE(?, failure_reason)
            WHERE action_id = ?
            """,
            (status, now, failure_reason, action_id),
        )
        conn.commit()
    finally:
        conn.close()


def load_action_record(action_id: str, db_path: Path) -> ActionRecord | None:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM action_records WHERE action_id = ?",
            (action_id,),
        ).fetchone()
        if row is None:
            return None
        return _row_to_record(row)
    finally:
        conn.close()


def _ensure_action_table(conn: sqlite3.Connection) -> None:
    conn.executescript(_ACTION_SCHEMA)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(action_records)")}
    if "failure_reason" not in cols:
        conn.execute("ALTER TABLE action_records ADD COLUMN failure_reason TEXT")
    if "auto_merge_after_ci" not in cols:
        conn.execute(
            "ALTER TABLE action_records ADD COLUMN auto_merge_after_ci INTEGER NOT NULL DEFAULT 1"
        )
    if "auto_merge_candidate_ids" not in cols:
        conn.execute(
            "ALTER TABLE action_records ADD COLUMN auto_merge_candidate_ids TEXT NOT NULL DEFAULT '[]'"
        )
    conn.commit()


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection(db_path)
    init_db(conn)
    _ensure_action_table(conn)
    return conn


def ensure_table(db_path: Path) -> None:
    conn = _connect(db_path)
    conn.close()


def _outcome_to_dict(outcome: PROutcome) -> dict[str, Any]:
    return asdict(outcome)


def _outcome_from_dict(data: dict[str, Any]) -> PROutcome:
    return PROutcome(
        candidate_id=str(data["candidate_id"]),
        package=str(data.get("package", "")),
        from_version=str(data.get("from_version", "")),
        to_version=str(data.get("to_version", "")),
        fix_kind=str(data.get("fix_kind", "")),
        status=str(data.get("status", "pending")),
        pr_number=data.get("pr_number"),
        pr_url=data.get("pr_url"),
        error=data.get("error"),
    )


def _row_to_record(row: sqlite3.Row) -> ActionRecord:
    completed_raw = row["completed_at"]
    return ActionRecord(
        action_id=row["action_id"],
        scan_hash=row["scan_hash"],
        repo_display=row["repo_display"],
        status=row["status"],
        started_at=datetime.fromisoformat(row["started_at"]),
        completed_at=(datetime.fromisoformat(completed_raw) if completed_raw else None),
        selected_candidate_ids=json.loads(row["selected_candidate_ids"]),
        pr_outcomes=[_outcome_from_dict(item) for item in json.loads(row["pr_outcomes"])],
        failure_reason=row["failure_reason"],
        auto_merge_after_ci=bool(row["auto_merge_after_ci"]),
        auto_merge_candidate_ids=json.loads(row["auto_merge_candidate_ids"]),
    )


def _persist_pr_outcomes(
    conn: sqlite3.Connection,
    action_id: str,
    outcomes: list[PROutcome],
) -> None:
    conn.execute(
        "UPDATE action_records SET pr_outcomes = ? WHERE action_id = ?",
        (json.dumps([_outcome_to_dict(o) for o in outcomes]), action_id),
    )
    conn.commit()
