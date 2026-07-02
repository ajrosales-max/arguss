"""SQLite-backed registry for Mode C wait-and-merge action runs."""

from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from arguss.core.cache import get_connection, init_db
from arguss.core.models import FixTier
from arguss.engine.propose import ProposalEntry
from arguss.settings import settings
from arguss.web.github_action import ActionResult

ActionRunState = Literal["running", "completed"]

CandidateState = Literal[
    "pr_opened",
    "ci_running",
    "merged",
    "ci_failed",
    "no_checks",
    "sha_conflict",
    "timed_out",
    "killed",
    "head_sha_unresolved",
]

MergeAuthorization = Literal["engine", "human_override"]

TERMINAL_CANDIDATE_STATES: frozenset[CandidateState] = frozenset(
    (
        "merged",
        "ci_failed",
        "no_checks",
        "sha_conflict",
        "timed_out",
        "killed",
        "head_sha_unresolved",
    )
)


@dataclass
class ActionRunCandidate:
    id: str
    action_run_id: str
    candidate_id: str
    package: str
    from_version: str
    to_version: str
    state: CandidateState
    updated_at: datetime
    pr_number: int | None = None
    head_sha: str | None = None
    state_detail: str | None = None
    merge_authorization: MergeAuthorization = "engine"


@dataclass
class ActionRun:
    id: str
    scan_hash: str
    mode: str
    created_at: datetime
    state: ActionRunState
    scan_ref: str | None = None
    wizard_action_id: str | None = None
    candidates: list[ActionRunCandidate] = field(default_factory=list)


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection(db_path)
    init_db(conn)
    return conn


def create_action_run(
    scan_hash: str,
    mode: str,
    db_path: Path,
    *,
    scan_ref: str | None = None,
    wizard_action_id: str | None = None,
) -> ActionRun:
    run_id = str(uuid.uuid4())
    now = datetime.now(UTC)
    conn = _connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO action_run (
                id, scan_hash, scan_ref, mode, created_at, state, wizard_action_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                scan_hash,
                scan_ref,
                mode,
                now.isoformat(),
                "running",
                wizard_action_id,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return ActionRun(
        id=run_id,
        scan_hash=scan_hash,
        mode=mode,
        created_at=now,
        state="running",
        scan_ref=scan_ref,
        wizard_action_id=wizard_action_id,
        candidates=[],
    )


def add_action_run_candidate(
    action_run_id: str,
    candidate_id: str,
    package: str,
    from_version: str,
    to_version: str,
    db_path: Path,
    *,
    state: CandidateState = "pr_opened",
    pr_number: int | None = None,
    head_sha: str | None = None,
    state_detail: str | None = None,
    merge_authorization: MergeAuthorization = "engine",
) -> ActionRunCandidate:
    row_id = str(uuid.uuid4())
    now = datetime.now(UTC)
    conn = _connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO action_run_candidate (
                id, action_run_id, candidate_id, package, from_version, to_version,
                pr_number, head_sha, state, state_detail, merge_authorization, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row_id,
                action_run_id,
                candidate_id,
                package,
                from_version,
                to_version,
                pr_number,
                head_sha,
                state,
                state_detail,
                merge_authorization,
                now.isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return ActionRunCandidate(
        id=row_id,
        action_run_id=action_run_id,
        candidate_id=candidate_id,
        package=package,
        from_version=from_version,
        to_version=to_version,
        state=state,
        updated_at=now,
        pr_number=pr_number,
        head_sha=head_sha,
        state_detail=state_detail,
        merge_authorization=merge_authorization,
    )


def update_action_run_candidate(
    candidate_row_id: str,
    db_path: Path,
    *,
    state: CandidateState | None = None,
    pr_number: int | None = None,
    head_sha: str | None = None,
    state_detail: str | None = None,
    merge_authorization: MergeAuthorization | None = None,
) -> ActionRunCandidate | None:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM action_run_candidate WHERE id = ?",
            (candidate_row_id,),
        ).fetchone()
        if row is None:
            return None
        now = datetime.now(UTC)
        new_state: CandidateState = state if state is not None else row["state"]
        new_pr = pr_number if pr_number is not None else row["pr_number"]
        new_head = head_sha if head_sha is not None else row["head_sha"]
        new_detail = state_detail if state_detail is not None else row["state_detail"]
        new_auth: MergeAuthorization = (
            merge_authorization if merge_authorization is not None else row["merge_authorization"]
        )
        conn.execute(
            """
            UPDATE action_run_candidate
            SET state = ?, pr_number = ?, head_sha = ?, state_detail = ?,
                merge_authorization = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                new_state,
                new_pr,
                new_head,
                new_detail,
                new_auth,
                now.isoformat(),
                candidate_row_id,
            ),
        )
        conn.commit()
        updated = conn.execute(
            "SELECT * FROM action_run_candidate WHERE id = ?",
            (candidate_row_id,),
        ).fetchone()
        return _row_to_candidate(updated)
    finally:
        conn.close()


def is_action_run_terminal(run: ActionRun) -> bool:
    if run.state == "completed":
        return True
    if not run.candidates:
        return False
    return all(c.state in TERMINAL_CANDIDATE_STATES for c in run.candidates)


def candidate_state_badge_class(state: CandidateState) -> str:
    """CSS class for merge-status badge styling in dashboard partials."""
    return {
        "pr_opened": "merge-status--pending",
        "ci_running": "merge-status--running",
        "merged": "merge-status--merged",
        "ci_failed": "merge-status--failed",
        "no_checks": "merge-status--warning",
        "sha_conflict": "merge-status--warning",
        "timed_out": "merge-status--failed",
        "killed": "merge-status--failed",
        "head_sha_unresolved": "merge-status--failed",
    }.get(state, "merge-status--pending")


def mark_action_run_completed(action_run_id: str, db_path: Path) -> None:
    conn = _connect(db_path)
    try:
        conn.execute(
            "UPDATE action_run SET state = ? WHERE id = ?",
            ("completed", action_run_id),
        )
        conn.commit()
    finally:
        conn.close()


def _fetch_action_run_row(action_run_id: str, db_path: Path) -> ActionRun | None:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM action_run WHERE id = ?",
            (action_run_id,),
        ).fetchone()
        if row is None:
            return None
        candidate_rows = conn.execute(
            """
            SELECT * FROM action_run_candidate
            WHERE action_run_id = ?
            ORDER BY updated_at ASC
            """,
            (action_run_id,),
        ).fetchall()
        return _row_to_run(row, [_row_to_candidate(r) for r in candidate_rows])
    finally:
        conn.close()


def _reconcile_stale_running_run(run: ActionRun, db_path: Path) -> ActionRun:
    """Finalize runs left ``running`` after process death or deploy."""
    if run.state != "running":
        return run
    age_seconds = (datetime.now(UTC) - run.created_at).total_seconds()
    threshold = float(settings.mode_c_merge_wait_cap_seconds) + 300.0
    if age_seconds <= threshold:
        return run
    for candidate in run.candidates:
        if candidate.state not in TERMINAL_CANDIDATE_STATES:
            update_action_run_candidate(
                candidate.id,
                db_path,
                state="timed_out",
                state_detail="merge wait interrupted or exceeded",
            )
    mark_action_run_completed(run.id, db_path)
    refreshed = _fetch_action_run_row(run.id, db_path)
    return refreshed if refreshed is not None else run


def finalize_action_run_if_terminal(action_run_id: str, db_path: Path) -> bool:
    run = load_action_run(action_run_id, db_path)
    if run is None:
        return False
    if run.state == "completed":
        return True
    if not is_action_run_terminal(run):
        return False
    conn = _connect(db_path)
    try:
        conn.execute(
            "UPDATE action_run SET state = ? WHERE id = ?",
            ("completed", action_run_id),
        )
        conn.commit()
    finally:
        conn.close()
    return True


def load_action_run(action_run_id: str, db_path: Path) -> ActionRun | None:
    run = _fetch_action_run_row(action_run_id, db_path)
    if run is None:
        return None
    return _reconcile_stale_running_run(run, db_path)


def load_action_run_by_wizard_action_id(
    wizard_action_id: str,
    db_path: Path,
) -> ActionRun | None:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM action_run WHERE wizard_action_id = ?",
            (wizard_action_id,),
        ).fetchone()
        if row is None:
            return None
        candidate_rows = conn.execute(
            """
            SELECT * FROM action_run_candidate
            WHERE action_run_id = ?
            ORDER BY updated_at ASC
            """,
            (row["id"],),
        ).fetchall()
        return _row_to_run(row, [_row_to_candidate(r) for r in candidate_rows])
    finally:
        conn.close()


def candidate_to_dict(candidate: ActionRunCandidate) -> dict[str, Any]:
    return {
        "id": candidate.id,
        "action_run_id": candidate.action_run_id,
        "candidate_id": candidate.candidate_id,
        "package": candidate.package,
        "from_version": candidate.from_version,
        "to_version": candidate.to_version,
        "pr_number": candidate.pr_number,
        "head_sha": candidate.head_sha,
        "state": candidate.state,
        "state_detail": candidate.state_detail,
        "merge_authorization": candidate.merge_authorization,
        "updated_at": candidate.updated_at.isoformat(),
    }


def action_run_to_dict(run: ActionRun) -> dict[str, Any]:
    return {
        "id": run.id,
        "scan_hash": run.scan_hash,
        "scan_ref": run.scan_ref,
        "mode": run.mode,
        "created_at": run.created_at.isoformat(),
        "state": run.state,
        "terminal": is_action_run_terminal(run),
        "wizard_action_id": run.wizard_action_id,
        "candidates": [candidate_to_dict(c) for c in run.candidates],
    }


def _row_to_candidate(row: sqlite3.Row) -> ActionRunCandidate:
    auth = row["merge_authorization"]
    merge_auth: MergeAuthorization = auth if auth in ("engine", "human_override") else "engine"
    return ActionRunCandidate(
        id=row["id"],
        action_run_id=row["action_run_id"],
        candidate_id=row["candidate_id"],
        package=row["package"],
        from_version=row["from_version"],
        to_version=row["to_version"],
        state=row["state"],
        updated_at=datetime.fromisoformat(row["updated_at"]),
        pr_number=row["pr_number"],
        head_sha=row["head_sha"],
        state_detail=row["state_detail"],
        merge_authorization=merge_auth,
    )


def _row_to_run(row: sqlite3.Row, candidates: list[ActionRunCandidate]) -> ActionRun:
    return ActionRun(
        id=row["id"],
        scan_hash=row["scan_hash"],
        scan_ref=row["scan_ref"],
        mode=row["mode"],
        created_at=datetime.fromisoformat(row["created_at"]),
        state=row["state"],
        wizard_action_id=row["wizard_action_id"],
        candidates=candidates,
    )


def populate_action_run_candidates(
    action_run_id: str,
    entries: Sequence[ProposalEntry],
    actions: Sequence[ActionResult],
    db_path: Path,
) -> list[ActionRunCandidate]:
    """Register merge-tracked candidates from PR action outcomes."""
    entry_by_id = {entry.candidate.candidate_id: entry for entry in entries}
    created: list[ActionRunCandidate] = []
    for action in actions:
        if action.status not in ("opened", "already_exists"):
            continue
        entry = entry_by_id.get(action.candidate_id)
        if entry is None:
            continue
        merge_auth: MergeAuthorization = (
            "engine" if entry.verdict.tier is FixTier.AUTO_MERGE else "human_override"
        )
        created.append(
            add_action_run_candidate(
                action_run_id,
                action.candidate_id,
                entry.candidate.package,
                entry.candidate.from_version,
                entry.candidate.to_version,
                db_path,
                pr_number=action.pr_number,
                head_sha=action.head_sha,
                merge_authorization=merge_auth,
            )
        )
    return created
