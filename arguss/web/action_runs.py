"""SQLite-backed registry for Mode C wait-and-merge action runs."""

from __future__ import annotations

import json
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
    "pr_only",
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
        "pr_only",
        "merged",
        "ci_failed",
        "no_checks",
        "sha_conflict",
        "timed_out",
        "killed",
        "head_sha_unresolved",
    )
)

_NO_MERGE_AUTHORIZATION = ""


class DeclineMergeAuthorizationError(Exception):
    """Raised when merge authorization is requested for a DECLINE-tier candidate."""


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
    merge_authorization: MergeAuthorization | None = None
    engine_score: int | None = None
    veto_signals: tuple[str, ...] = ()
    pr_authorization_appended: bool = False


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


def _merge_auth_db_value(merge_authorization: MergeAuthorization | None) -> str:
    if merge_authorization is None:
        return _NO_MERGE_AUTHORIZATION
    return merge_authorization


def _merge_authorization_for_tier(tier: FixTier) -> MergeAuthorization:
    if tier is FixTier.AUTO_MERGE:
        return "engine"
    if tier is FixTier.REVIEW_REQUIRED:
        return "human_override"
    raise DeclineMergeAuthorizationError(
        f"cannot authorize merge for tier {tier!s}",
    )


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
    merge_authorization: MergeAuthorization | None = "engine",
    engine_score: int | None = None,
    veto_signals: Sequence[str] | None = None,
    pr_authorization_appended: bool = False,
) -> ActionRunCandidate:
    row_id = str(uuid.uuid4())
    now = datetime.now(UTC)
    conn = _connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO action_run_candidate (
                id, action_run_id, candidate_id, package, from_version, to_version,
                pr_number, head_sha, state, state_detail, merge_authorization,
                engine_score, veto_signals, pr_authorization_appended, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                _merge_auth_db_value(merge_authorization),
                engine_score,
                _veto_signals_db_value(veto_signals),
                _pr_auth_appended_db_value(pr_authorization_appended),
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
        engine_score=engine_score,
        veto_signals=tuple(veto_signals or ()),
        pr_authorization_appended=pr_authorization_appended,
    )


_UNSET_MERGE_AUTHORIZATION: object = object()


def update_action_run_candidate(
    candidate_row_id: str,
    db_path: Path,
    *,
    state: CandidateState | None = None,
    pr_number: int | None = None,
    head_sha: str | None = None,
    state_detail: str | None = None,
    merge_authorization: MergeAuthorization | None | object = _UNSET_MERGE_AUTHORIZATION,
    engine_score: int | None | object = _UNSET_MERGE_AUTHORIZATION,
    veto_signals: Sequence[str] | None | object = _UNSET_MERGE_AUTHORIZATION,
    pr_authorization_appended: bool | None = None,
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
        if merge_authorization is _UNSET_MERGE_AUTHORIZATION:
            new_auth_db = row["merge_authorization"]
        else:
            new_auth_db = _merge_auth_db_value(merge_authorization)  # type: ignore[arg-type]
        if engine_score is _UNSET_MERGE_AUTHORIZATION:
            new_engine_score = row["engine_score"]
        else:
            new_engine_score = engine_score  # type: ignore[assignment]
        if veto_signals is _UNSET_MERGE_AUTHORIZATION:
            new_veto_db = row["veto_signals"]
        else:
            new_veto_db = _veto_signals_db_value(veto_signals)  # type: ignore[arg-type]
        if pr_authorization_appended is None:
            new_pr_auth = row["pr_authorization_appended"]
        else:
            new_pr_auth = _pr_auth_appended_db_value(pr_authorization_appended)
        conn.execute(
            """
            UPDATE action_run_candidate
            SET state = ?, pr_number = ?, head_sha = ?, state_detail = ?,
                merge_authorization = ?, engine_score = ?, veto_signals = ?,
                pr_authorization_appended = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                new_state,
                new_pr,
                new_head,
                new_detail,
                new_auth_db,
                new_engine_score,
                new_veto_db,
                new_pr_auth,
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
        "pr_only": "merge-status--neutral",
    }.get(state, "merge-status--pending")


def merge_authorization_commit_message(
    merge_authorization: MergeAuthorization,
    *,
    engine_score: int | None,
    veto_signals: Sequence[str],
) -> str:
    if merge_authorization == "engine":
        score = engine_score if engine_score is not None else 0
        return f"Merged by Arguss under engine envelope (AUTO_MERGE, score {score})"
    signal_names = ", ".join(veto_signals) if veto_signals else "none"
    return f"Merge authorized by operator; engine verdict was REVIEW_REQUIRED ({signal_names})"


def merge_authorization_pr_line(commit_message: str) -> str:
    return f"Armed for auto-merge: {commit_message}"


def candidate_state_label(state: CandidateState) -> str:
    if state == "pr_only":
        return "PR opened, review manually"
    return state.replace("_", " ")


def _veto_signals_db_value(veto_signals: Sequence[str] | None) -> str:
    if not veto_signals:
        return "[]"
    return json.dumps(list(veto_signals))


def _veto_signals_from_db(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ()
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return ()
    if not isinstance(parsed, list):
        return ()
    return tuple(str(item) for item in parsed)


def _pr_auth_appended_from_db(value: int | None) -> bool:
    return bool(value)


def _pr_auth_appended_db_value(appended: bool) -> int:
    return 1 if appended else 0


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
        "engine_score": candidate.engine_score,
        "veto_signals": list(candidate.veto_signals),
        "pr_authorization_appended": candidate.pr_authorization_appended,
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
    if auth == _NO_MERGE_AUTHORIZATION:
        merge_auth = None
    elif auth in ("engine", "human_override"):
        merge_auth = auth
    else:
        merge_auth = None
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
        engine_score=row["engine_score"],
        veto_signals=_veto_signals_from_db(row["veto_signals"]),
        pr_authorization_appended=_pr_auth_appended_from_db(row["pr_authorization_appended"]),
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
    *,
    auto_merge_candidate_ids: set[str],
) -> list[ActionRunCandidate]:
    """Register all opened PRs; mark merge-selected rows for wait-and-merge."""
    entry_by_id = {entry.candidate.candidate_id: entry for entry in entries}
    for candidate_id in auto_merge_candidate_ids:
        entry = entry_by_id.get(candidate_id)
        if entry is not None and entry.verdict.tier is FixTier.DECLINE:
            raise DeclineMergeAuthorizationError(
                f"cannot authorize merge for DECLINE candidate {candidate_id}",
            )
    created: list[ActionRunCandidate] = []
    for action in actions:
        if action.status not in ("opened", "already_exists"):
            continue
        entry = entry_by_id.get(action.candidate_id)
        if entry is None:
            continue
        if action.candidate_id in auto_merge_candidate_ids:
            merge_auth = _merge_authorization_for_tier(entry.verdict.tier)
            state: CandidateState = "pr_opened"
            engine_score = entry.verdict.score
            veto_signals = entry.verdict.veto_signals
        else:
            merge_auth = None
            state = "pr_only"
            engine_score = None
            veto_signals = None
        created.append(
            add_action_run_candidate(
                action_run_id,
                action.candidate_id,
                entry.candidate.package,
                entry.candidate.from_version,
                entry.candidate.to_version,
                db_path,
                state=state,
                pr_number=action.pr_number,
                head_sha=action.head_sha,
                merge_authorization=merge_auth,
                engine_score=engine_score,
                veto_signals=veto_signals,
            )
        )
    return created
