"""Shared Mode C scan workflow and in-memory SSE stream registry."""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
import uuid
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status
from fastapi.concurrency import run_in_threadpool

from arguss.core.models import FixTier
from arguss.core.parser import ParserError
from arguss.core.serialization import (
    attach_executive_summary,
    finalize_scan_payload,
)
from arguss.engine.propose import ProposalEntry, ProposalReport, propose_fixes
from arguss.explanations.scan_cache import scan_input_hash
from arguss.lenses._zizmor_client import ZizmorClientError
from arguss.settings import settings
from arguss.web.action_merge import spawn_action_merge_task
from arguss.web.action_records import mirror_action_event
from arguss.web.action_runs import (
    create_action_run,
    populate_action_run_candidates,
)
from arguss.web.git_clone import GitCloneError, shallow_clone
from arguss.web.github_action import (
    ActionResult,
    GitHubActionError,
    ModeCEventEmitter,
    PatInsufficientError,
    http_detail_for_github_action_error,
    run_mode_c_actions,
    validate_pat_before_clone,
)
from arguss.web.github_url import InvalidGitHubURLError, parse_github_url
from arguss.web.scan_inputs import save_scan_inputs
from arguss.web.url_scan import build_scan_meta
from arguss.web.wizard import (
    WizardSelectionError,
    filter_entries_for_action,
    http_exception_for_selection_error,
    selection_error_scan_failed_event,
    validate_selection_against_fresh_report,
)

_LOG = logging.getLogger(__name__)
_INTERNAL_DETAIL = "Internal error during analysis"


def _normalize_ref(ref: str) -> str:
    stripped = ref.strip()
    return stripped if stripped else "HEAD"


def _log_ref_mismatch(
    *,
    repo_display: str,
    action_ref: str,
    assessment_ref: str,
    action_id: str | None,
) -> None:
    _LOG.error(
        "mode C action ref diverges from assessment ref",
        extra={
            "repo": repo_display,
            "action_ref": action_ref,
            "assessment_ref": assessment_ref,
            "action_id": action_id,
        },
    )


def _clone_error_status(exc: GitCloneError) -> int:
    if exc.kind == GitCloneError.KIND_GIT_EXECUTABLE:
        return status.HTTP_500_INTERNAL_SERVER_ERROR
    if exc.kind == GitCloneError.KIND_TIMEOUT:
        return status.HTTP_504_GATEWAY_TIMEOUT
    return status.HTTP_404_NOT_FOUND


def _clone_error_detail(exc: GitCloneError) -> str:
    if exc.kind == GitCloneError.KIND_GIT_EXECUTABLE:
        return "git executable not available on server"
    if exc.kind == GitCloneError.KIND_TIMEOUT:
        return "Clone took too long; repository may be too large"
    if exc.kind == GitCloneError.KIND_REF_NOT_FOUND and exc.ref:
        return f"Ref '{exc.ref}' not found in repository"
    return "Repository not found or not accessible"


def _effective_auto_merge_candidate_ids(
    action_entries: Sequence[ProposalEntry],
    mergeable_actions: Sequence[ActionResult],
    auto_merge_candidate_ids: frozenset[str] | None,
) -> frozenset[str]:
    mergeable_ids = {a.candidate_id for a in mergeable_actions}
    if auto_merge_candidate_ids is None:
        return frozenset(
            e.candidate.candidate_id
            for e in action_entries
            if e.verdict.tier is FixTier.AUTO_MERGE and e.candidate.candidate_id in mergeable_ids
        )
    return frozenset(cid for cid in auto_merge_candidate_ids if cid in mergeable_ids)


_STREAM_SENTINEL: object = object()


@dataclass
class ScanWithActionResult:
    """Outcome of a full Mode C scan (analysis + actions)."""

    report: ProposalReport
    actions: list[ActionResult]
    payload: dict[str, Any]
    scan_hash: str
    action_run_id: str | None = None


@dataclass
class _ScanStream:
    queue: asyncio.Queue[dict[str, Any] | object]
    task: asyncio.Task[None] | None = None


_streams: dict[str, _ScanStream] = {}
_streams_lock = asyncio.Lock()


async def register_scan_stream() -> tuple[str, asyncio.Queue[dict[str, Any] | object]]:
    """Create a new scan_id and event queue for SSE consumers."""
    scan_id = uuid.uuid4().hex
    queue: asyncio.Queue[dict[str, Any] | object] = asyncio.Queue()
    async with _streams_lock:
        _streams[scan_id] = _ScanStream(queue=queue)
    return scan_id, queue


async def get_scan_stream_queue(
    scan_id: str,
) -> asyncio.Queue[dict[str, Any] | object] | None:
    async with _streams_lock:
        handle = _streams.get(scan_id)
        if handle is None:
            return None
        return handle.queue


async def unregister_scan_stream(scan_id: str) -> None:
    async with _streams_lock:
        handle = _streams.pop(scan_id, None)
    if handle is not None and handle.task is not None and not handle.task.done():
        handle.task.cancel()


def _queue_emitter(
    queue: asyncio.Queue[dict[str, Any] | object],
) -> ModeCEventEmitter:
    async def emit(event: dict[str, Any]) -> None:
        await queue.put(event)

    return emit


def _mirroring_queue_emitter(
    queue: asyncio.Queue[dict[str, Any] | object],
    action_id: str,
    db_path: Path,
    mirror_lock: asyncio.Lock,
) -> ModeCEventEmitter:
    inner = _queue_emitter(queue)

    async def emit(event: dict[str, Any]) -> None:
        await inner(event)
        async with mirror_lock:
            try:
                await run_in_threadpool(mirror_action_event, action_id, event, db_path)
            except Exception:
                _LOG.exception(
                    "action record mirror failed",
                    extra={"action_id": action_id},
                )

    return emit


async def execute_scan_with_action(
    *,
    url: str,
    pat: str,
    ref: str = "HEAD",
    assessment_ref: str | None = None,
    event_emitter: ModeCEventEmitter | None = None,
    selected_candidate_ids: list[str] | None = None,
    action_id: str | None = None,
    auto_merge_candidate_ids: frozenset[str] | None = None,
) -> ScanWithActionResult:
    """Clone, analyze, and run Mode C actions. Optional event_emitter for SSE."""
    try:
        parsed = parse_github_url(url)
    except InvalidGitHubURLError as exc:
        if event_emitter is not None:
            await event_emitter({"type": "scan_failed", "reason": str(exc)})
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    repo_display = f"{parsed.owner}/{parsed.name}"
    clone_ref = _normalize_ref(ref)
    if assessment_ref is not None and _normalize_ref(assessment_ref) != clone_ref:
        _log_ref_mismatch(
            repo_display=repo_display,
            action_ref=clone_ref,
            assessment_ref=_normalize_ref(assessment_ref),
            action_id=action_id,
        )

    _LOG.info(
        "mode C action workflow started",
        extra={"repo": repo_display, "ref": clone_ref, "action_id": action_id},
    )

    if event_emitter is not None:
        await event_emitter(
            {
                "type": "scan_started",
                "repo": repo_display,
                "ref": clone_ref,
            },
        )

    try:
        try:
            await validate_pat_before_clone(
                parsed.owner,
                parsed.name,
                pat,
                event_emitter=event_emitter,
            )
        except PatInsufficientError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="PAT does not have push permission on the target repository",
            ) from None
        except GitHubActionError as exc:
            code, detail = http_detail_for_github_action_error(exc)
            raise HTTPException(status_code=code, detail=detail) from exc

        with tempfile.TemporaryDirectory(prefix="arguss-scan-action-") as tmp:
            tmp_path = Path(tmp)
            clone_target = tmp_path / parsed.name

            _LOG.info(
                "mode C clone starting",
                extra={"repo": repo_display, "ref": clone_ref, "action_id": action_id},
            )
            try:
                work_tree = await run_in_threadpool(
                    shallow_clone,
                    parsed.clone_url,
                    clone_target,
                    clone_ref,
                )
            except GitCloneError as exc:
                _LOG.error(
                    "mode C clone failed: %s: %s",
                    type(exc).__name__,
                    exc,
                    extra={"repo": repo_display, "ref": clone_ref, "action_id": action_id},
                )
                code = _clone_error_status(exc)
                detail = _clone_error_detail(exc)
                if event_emitter is not None:
                    await event_emitter({"type": "scan_failed", "reason": detail})
                raise HTTPException(status_code=code, detail=detail) from exc

            lockfile_path = work_tree / "package-lock.json"
            if not lockfile_path.is_file():
                detail = "Repository does not contain a package-lock.json"
                if event_emitter is not None:
                    await event_emitter({"type": "scan_failed", "reason": detail})
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=detail,
                )

            if event_emitter is not None:
                await event_emitter({"type": "analysis_started"})

            try:
                report = await run_in_threadpool(
                    propose_fixes,
                    lockfile_path,
                    work_tree,
                    repo_identity=parsed.repo_identity,
                )
            except ParserError as exc:
                _LOG.warning("lockfile parse failed during scan_with_action: %s", exc)
                detail = f"Could not parse lockfile: {exc}"
                if event_emitter is not None:
                    await event_emitter({"type": "scan_failed", "reason": detail})
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=detail,
                ) from exc
            except ZizmorClientError as exc:
                _LOG.exception("pipeline snapshot failed during scan_with_action")
                if event_emitter is not None:
                    await event_emitter({"type": "scan_failed", "reason": _INTERNAL_DETAIL})
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=_INTERNAL_DETAIL,
                ) from exc
            except Exception as exc:
                _LOG.exception("unexpected error during scan_with_action analysis")
                if event_emitter is not None:
                    await event_emitter({"type": "scan_failed", "reason": _INTERNAL_DETAIL})
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=_INTERNAL_DETAIL,
                ) from exc

            if event_emitter is not None:
                await event_emitter({"type": "analysis_complete"})

            try:
                if selected_candidate_ids is not None:
                    validate_selection_against_fresh_report(
                        report.entries,
                        selected_candidate_ids,
                    )
                action_entries = filter_entries_for_action(
                    report.entries,
                    selected_candidate_ids,
                )
            except WizardSelectionError as exc:
                if event_emitter is not None:
                    await event_emitter(selection_error_scan_failed_event(exc))
                raise http_exception_for_selection_error(exc) from exc

            try:
                actions = await run_mode_c_actions(
                    action_entries,
                    work_tree,
                    parsed.owner,
                    parsed.name,
                    pat,
                    event_emitter=event_emitter,
                )
            except GitHubActionError as exc:
                _LOG.error(
                    "mode C GitHub action failed: %s: %s",
                    type(exc).__name__,
                    exc,
                    extra={"repo": repo_display, "ref": ref, "action_id": action_id},
                )
                code, detail = http_detail_for_github_action_error(exc)
                if event_emitter is not None:
                    await event_emitter({"type": "scan_failed", "reason": detail})
                raise HTTPException(status_code=code, detail=detail) from exc

            payload = finalize_scan_payload(
                report,
                lockfile_path,
                scan_meta=build_scan_meta(
                    repo_display=f"{parsed.owner}/{parsed.name}",
                    ref=clone_ref,
                    mode="C",
                    lockfile_path=lockfile_path,
                ),
                actions=actions,
            )

            pre_enriched = attach_executive_summary(dict(payload))
            pre_scan_hash = scan_input_hash(pre_enriched)
            mergeable = [a for a in actions if a.status in ("opened", "already_exists")]
            effective_merge_ids = _effective_auto_merge_candidate_ids(
                action_entries, mergeable, auto_merge_candidate_ids
            )
            action_run_id: str | None = None
            if effective_merge_ids:
                action_run = create_action_run(
                    pre_scan_hash,
                    "C",
                    settings.db_path,
                    scan_ref=clone_ref,
                    wizard_action_id=action_id,
                )
                action_run_id = action_run.id
                populate_action_run_candidates(
                    action_run.id,
                    action_entries,
                    actions,
                    settings.db_path,
                    auto_merge_candidate_ids=set(effective_merge_ids),
                )
                spawn_action_merge_task(
                    action_run.id,
                    parsed.owner,
                    parsed.name,
                    pat,
                    settings.db_path,
                )

            payload["action_run_id"] = action_run_id
            enriched = attach_executive_summary(payload)
            scan_hash = scan_input_hash(enriched)
            save_scan_inputs(scan_hash, "C", url, clone_ref, settings.db_path)

            if event_emitter is not None:
                await event_emitter(
                    {
                        "type": "results_ready",
                        "scan_hash": scan_hash,
                        "action_run_id": action_run_id,
                    },
                )

            if action_id is not None:
                from arguss.web.action_records import update_action_record_scan_hash

                update_action_record_scan_hash(action_id, scan_hash, settings.db_path)

            return ScanWithActionResult(
                report=report,
                actions=actions,
                payload=enriched,
                scan_hash=scan_hash,
                action_run_id=action_run_id,
            )
    except HTTPException:
        raise
    except Exception as exc:
        _LOG.exception("unexpected error in execute_scan_with_action")
        if event_emitter is not None:
            await event_emitter({"type": "scan_failed", "reason": _INTERNAL_DETAIL})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_INTERNAL_DETAIL,
        ) from exc


async def run_scan_background(
    scan_id: str,
    *,
    url: str,
    pat: str,
    ref: str = "HEAD",
    assessment_ref: str | None = None,
    selected_candidate_ids: list[str] | None = None,
    action_id: str | None = None,
    db_path: Path | None = None,
    auto_merge_candidate_ids: frozenset[str] | None = None,
) -> None:
    """Execute a scan and push events (then sentinel) onto the scan queue."""
    queue = await get_scan_stream_queue(scan_id)
    if queue is None:
        return

    mirror_lock = asyncio.Lock()

    if action_id and db_path is not None:
        emitter = _mirroring_queue_emitter(queue, action_id, db_path, mirror_lock)
    else:
        emitter = _queue_emitter(queue)

    async def emit_scan_failed(payload: dict[str, Any]) -> None:
        await queue.put(payload)
        if action_id and db_path is not None:
            async with mirror_lock:
                try:
                    await run_in_threadpool(mirror_action_event, action_id, payload, db_path)
                except Exception:
                    _LOG.exception(
                        "action record mirror failed on scan_failed",
                        extra={"action_id": action_id},
                    )

    try:
        await execute_scan_with_action(
            url=url,
            pat=pat,
            ref=ref,
            assessment_ref=assessment_ref,
            event_emitter=emitter,
            selected_candidate_ids=selected_candidate_ids,
            action_id=action_id,
            auto_merge_candidate_ids=auto_merge_candidate_ids,
        )
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        await emit_scan_failed({"type": "scan_failed", "reason": detail})
    except Exception as exc:
        _LOG.exception("background scan failed", extra={"scan_id": scan_id})
        await emit_scan_failed({"type": "scan_failed", "reason": str(exc)})
    finally:
        await queue.put(_STREAM_SENTINEL)


async def attach_background_task(scan_id: str, task: asyncio.Task[None]) -> None:
    async with _streams_lock:
        handle = _streams.get(scan_id)
        if handle is not None:
            handle.task = task


async def iter_sse_events(scan_id: str) -> AsyncIterator[dict[str, str]]:
    """Async generator of SSE event dicts for EventSourceResponse."""
    queue = await get_scan_stream_queue(scan_id)
    if queue is None:
        yield {
            "event": "scan_failed",
            "data": json.dumps({"reason": "Unknown or expired scan_id"}),
        }
        return

    try:
        while True:
            item = await queue.get()
            if item is _STREAM_SENTINEL:
                break
            if isinstance(item, dict):
                event_type = item.get("type", "message")
                yield {"event": event_type, "data": json.dumps(item)}
    finally:
        await unregister_scan_stream(scan_id)
