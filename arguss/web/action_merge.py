"""Background wait-and-merge task for Mode C auto-merge."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from arguss.engine.kill_switch import is_kill_switch_active
from arguss.settings import settings
from arguss.web.action_runs import (
    TERMINAL_CANDIDATE_STATES,
    ActionRunCandidate,
    finalize_action_run_if_terminal,
    load_action_run,
    update_action_run_candidate,
)
from arguss.web.github_action import _api_url, _github_headers

_LOG = logging.getLogger(__name__)
_HTTP_TIMEOUT_SECONDS = 30.0
_GREEN_CONCLUSIONS = frozenset({"success", "neutral", "skipped"})

# Strong refs so merge tasks are not GC'd mid-wait.
_MERGE_TASKS: set[asyncio.Task[None]] = set()


def spawn_action_merge_task(
    action_run_id: str,
    owner: str,
    name: str,
    pat: str,
    db_path: Path,
) -> asyncio.Task[None]:
    """Schedule wait-and-merge on the running loop.

    All Mode C entry paths (JSON ``/scan/with-action``, SSE ``run_scan_background``,
    wizard authorize → ``run_scan_background``) ``await execute_scan_with_action()``,
    so a running event loop is always present when this is called.
    """
    loop = asyncio.get_running_loop()
    task = loop.create_task(
        run_action_merge_task(action_run_id, owner, name, pat, db_path),
    )
    _MERGE_TASKS.add(task)
    task.add_done_callback(_MERGE_TASKS.discard)
    return task


def _check_runs_green(check_runs: list[dict[str, Any]]) -> bool:
    if not check_runs:
        return False
    for run in check_runs:
        if run.get("status") != "completed":
            return False
        conclusion = run.get("conclusion")
        if conclusion not in _GREEN_CONCLUSIONS:
            return False
    return True


def _check_runs_failed(check_runs: list[dict[str, Any]]) -> bool:
    for run in check_runs:
        if run.get("status") == "completed":
            conclusion = run.get("conclusion")
            if conclusion not in _GREEN_CONCLUSIONS:
                return True
    return False


def _fetch_check_runs(
    client: httpx.Client, owner: str, name: str, head_sha: str
) -> list[dict[str, Any]]:
    response = client.get(
        _api_url(owner, name, f"/commits/{head_sha}/check-runs"),
        params={"per_page": "100"},
    )
    if response.status_code != 200:
        return []
    try:
        payload = response.json()
    except ValueError:
        return []
    if not isinstance(payload, dict):
        return []
    check_runs = payload.get("check_runs")
    if not isinstance(check_runs, list):
        return []
    return [run for run in check_runs if isinstance(run, dict)]


def _fetch_pr_head_sha(client: httpx.Client, owner: str, name: str, pr_number: int) -> str | None:
    response = client.get(_api_url(owner, name, f"/pulls/{pr_number}"))
    if response.status_code != 200:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    head = payload.get("head")
    if not isinstance(head, dict):
        return None
    sha = head.get("sha")
    return sha if isinstance(sha, str) and sha else None


def _merge_pull_request(
    client: httpx.Client,
    owner: str,
    name: str,
    pr_number: int,
    head_sha: str,
) -> int:
    response = client.put(
        _api_url(owner, name, f"/pulls/{pr_number}/merge"),
        json={"sha": head_sha},
    )
    return response.status_code


async def _process_candidate(
    candidate: ActionRunCandidate,
    owner: str,
    name: str,
    db_path: Path,
    grace_period: float,
    first_no_checks_at: dict[str, float],
    run_with_client: Callable[[Callable[[httpx.Client], Any]], Any],
) -> None:
    if candidate.state in TERMINAL_CANDIDATE_STATES:
        return

    head_sha = candidate.head_sha
    if head_sha is None:
        pr_number = candidate.pr_number
        if pr_number is None:
            update_action_run_candidate(
                candidate.id,
                db_path,
                state="head_sha_unresolved",
                state_detail="missing pr_number for head sha lookup",
            )
            return
        resolved_pr = pr_number

        def _resolve_head(client: httpx.Client) -> str | None:
            return _fetch_pr_head_sha(client, owner, name, resolved_pr)

        head_sha = await asyncio.to_thread(run_with_client, _resolve_head)
        if head_sha is None:
            update_action_run_candidate(
                candidate.id,
                db_path,
                state="head_sha_unresolved",
                state_detail="could not resolve pull request head sha",
            )
            return
        update_action_run_candidate(candidate.id, db_path, head_sha=head_sha)
        refreshed = load_action_run(candidate.action_run_id, db_path)
        if refreshed is not None:
            for row in refreshed.candidates:
                if row.id == candidate.id:
                    candidate = row
                    break

    check_runs = await asyncio.to_thread(
        run_with_client,
        lambda client: _fetch_check_runs(client, owner, name, head_sha),
    )

    if not check_runs:
        now = time.monotonic()
        started = first_no_checks_at.setdefault(candidate.id, now)
        if now - started >= grace_period:
            update_action_run_candidate(
                candidate.id,
                db_path,
                state="no_checks",
                state_detail="no check runs observed before grace period elapsed",
            )
            return
        if candidate.state == "pr_opened":
            update_action_run_candidate(candidate.id, db_path, state="ci_running")
        return

    first_no_checks_at.pop(candidate.id, None)

    if _check_runs_failed(check_runs):
        update_action_run_candidate(
            candidate.id,
            db_path,
            state="ci_failed",
            state_detail="one or more check runs completed with a failing conclusion",
        )
        return

    if not _check_runs_green(check_runs):
        if candidate.state == "pr_opened":
            update_action_run_candidate(candidate.id, db_path, state="ci_running")
        return

    pr_number = candidate.pr_number
    if pr_number is None:
        update_action_run_candidate(
            candidate.id,
            db_path,
            state="head_sha_unresolved",
            state_detail="missing pr_number for merge",
        )
        return
    resolved_pr = pr_number

    def _do_merge(client: httpx.Client) -> int:
        return _merge_pull_request(client, owner, name, resolved_pr, head_sha)

    merge_status = await asyncio.to_thread(run_with_client, _do_merge)
    if merge_status == 200:
        update_action_run_candidate(candidate.id, db_path, state="merged")
        return
    if merge_status == 409:
        update_action_run_candidate(
            candidate.id,
            db_path,
            state="sha_conflict",
            state_detail="merge rejected because head sha changed",
        )


async def run_action_merge_task(
    action_run_id: str,
    owner: str,
    name: str,
    pat: str,
    db_path: Path,
) -> None:
    """Poll CI and merge eligible PRs. PAT must remain in this closure only."""
    poll_interval = settings.mode_c_ci_poll_interval_seconds
    grace_period = float(settings.mode_c_ci_grace_period_seconds)
    wait_cap = float(settings.mode_c_merge_wait_cap_seconds)
    started_at = time.monotonic()
    first_no_checks_at: dict[str, float] = {}
    headers = _github_headers(pat)

    def run_with_client(fn: Callable[[httpx.Client], Any]) -> Any:
        with httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS, headers=headers) as client:
            return fn(client)

    while True:
        if is_kill_switch_active():
            run = load_action_run(action_run_id, db_path)
            if run is not None:
                for candidate in run.candidates:
                    if candidate.state not in TERMINAL_CANDIDATE_STATES:
                        update_action_run_candidate(candidate.id, db_path, state="killed")
            finalize_action_run_if_terminal(action_run_id, db_path)
            return

        run = load_action_run(action_run_id, db_path)
        if run is None:
            return

        active = [c for c in run.candidates if c.state not in TERMINAL_CANDIDATE_STATES]
        if not active:
            finalize_action_run_if_terminal(action_run_id, db_path)
            return

        if time.monotonic() - started_at >= wait_cap:
            for candidate in active:
                update_action_run_candidate(
                    candidate.id,
                    db_path,
                    state="timed_out",
                    state_detail="merge wait cap elapsed before CI completed",
                )
            finalize_action_run_if_terminal(action_run_id, db_path)
            return

        for candidate in active:
            await _process_candidate(
                candidate,
                owner,
                name,
                db_path,
                grace_period,
                first_no_checks_at,
                run_with_client,
            )

        await asyncio.sleep(poll_interval)
