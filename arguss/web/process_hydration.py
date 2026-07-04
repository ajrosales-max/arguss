"""Build persisted state for the wizard /process page (refresh-safe)."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from arguss.web.action_records import ActionRecord
from arguss.web.action_runs import ActionRun
from arguss.web.completion_summary import counts_from_pr_outcomes


def build_process_hydration(
    record: ActionRecord | None,
    action_run: ActionRun | None,
) -> dict[str, Any]:
    """Serializable snapshot for hydrating /process after SSE stream expires."""
    if record is None:
        return {
            "has_record": False,
            "terminal": False,
            "status": None,
            "auto_merge_candidate_ids": [],
            "tracks_auto_merge": False,
            "action_run_id": None,
            "failure_reason": None,
            "pr_outcomes": [],
            "scan_complete": None,
        }

    counts = counts_from_pr_outcomes(record.pr_outcomes)
    terminal = record.status in ("completed", "partial", "failed")
    scan_complete: dict[str, int] | None = None
    if terminal and record.status != "failed" and record.pr_outcomes:
        scan_complete = {
            "succeeded": counts.opened,
            "already_exists": counts.already_exists,
            "failed": counts.failed,
            "skipped": counts.skipped,
            "total": len(record.pr_outcomes),
        }

    tracks_auto_merge = bool(record.auto_merge_candidate_ids) and action_run is not None
    action_run_id: str | None = None
    if tracks_auto_merge and action_run is not None:
        action_run_id = action_run.id

    return {
        "has_record": True,
        "terminal": terminal,
        "status": record.status,
        "auto_merge_candidate_ids": list(record.auto_merge_candidate_ids),
        "tracks_auto_merge": tracks_auto_merge,
        "action_run_id": action_run_id,
        "failure_reason": record.failure_reason,
        "pr_outcomes": [asdict(outcome) for outcome in record.pr_outcomes],
        "scan_complete": scan_complete,
    }
