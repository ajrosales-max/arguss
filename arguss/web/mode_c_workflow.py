"""Shared Mode C scan workflow and in-memory SSE stream registry."""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status
from fastapi.concurrency import run_in_threadpool

from arguss.core.parser import ParserError
from arguss.core.serialization import (
    attach_executive_summary,
    proposal_report_with_actions_payload,
)
from arguss.engine.propose import ProposalReport, propose_fixes
from arguss.explanations.scan_cache import scan_input_hash
from arguss.lenses._zizmor_client import ZizmorClientError
from arguss.web.git_clone import GitCloneError, shallow_clone
from arguss.web.github_action import (
    ActionResult,
    GitHubActionError,
    ModeCEventEmitter,
    PatInsufficientError,
    run_mode_c_actions,
)
from arguss.web.github_url import InvalidGitHubURLError, parse_github_url

_LOG = logging.getLogger(__name__)
_INTERNAL_DETAIL = "Internal error during analysis"


def _clone_error_status(exc: GitCloneError) -> int:
    if isinstance(exc.__cause__, subprocess.TimeoutExpired):
        return status.HTTP_504_GATEWAY_TIMEOUT
    if "timed out" in str(exc).lower():
        return status.HTTP_504_GATEWAY_TIMEOUT
    return status.HTTP_404_NOT_FOUND


_STREAM_SENTINEL: object = object()


@dataclass
class ScanWithActionResult:
    """Outcome of a full Mode C scan (analysis + actions)."""

    report: ProposalReport
    actions: list[ActionResult]
    payload: dict[str, Any]
    scan_hash: str


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


async def execute_scan_with_action(
    *,
    url: str,
    pat: str,
    ref: str = "HEAD",
    event_emitter: ModeCEventEmitter | None = None,
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

    if event_emitter is not None:
        await event_emitter(
            {
                "type": "scan_started",
                "repo": f"{parsed.owner}/{parsed.name}",
                "ref": ref,
            },
        )

    try:
        with tempfile.TemporaryDirectory(prefix="arguss-scan-action-") as tmp:
            tmp_path = Path(tmp)
            clone_target = tmp_path / parsed.name

            try:
                work_tree = await run_in_threadpool(
                    shallow_clone,
                    parsed.clone_url,
                    clone_target,
                )
            except GitCloneError as exc:
                code = _clone_error_status(exc)
                detail = (
                    "Clone took too long; repository may be too large"
                    if code == status.HTTP_504_GATEWAY_TIMEOUT
                    else "Repository not found or not accessible"
                )
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
                actions = await run_mode_c_actions(
                    report.entries,
                    work_tree,
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
                if exc.status_code == status.HTTP_401_UNAUTHORIZED:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid or expired PAT",
                    ) from exc
                if exc.status_code == status.HTTP_403_FORBIDDEN:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="PAT lacks repo scope on this repository",
                    ) from exc
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=_INTERNAL_DETAIL,
                ) from exc

            payload = proposal_report_with_actions_payload(report, actions)
            enriched = attach_executive_summary(payload)
            scan_hash = scan_input_hash(enriched)

            if event_emitter is not None:
                await event_emitter(
                    {
                        "type": "results_ready",
                        "scan_hash": scan_hash,
                    },
                )

            return ScanWithActionResult(
                report=report,
                actions=actions,
                payload=enriched,
                scan_hash=scan_hash,
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
) -> None:
    """Execute a scan and push events (then sentinel) onto the scan queue."""
    queue = await get_scan_stream_queue(scan_id)
    if queue is None:
        return

    emitter = _queue_emitter(queue)

    try:
        await execute_scan_with_action(
            url=url,
            pat=pat,
            ref=ref,
            event_emitter=emitter,
        )
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        await queue.put({"type": "scan_failed", "reason": detail})
    except Exception as exc:
        _LOG.exception("background scan failed", extra={"scan_id": scan_id})
        await queue.put({"type": "scan_failed", "reason": str(exc)})
    finally:
        await queue.put(_STREAM_SENTINEL)


async def attach_background_task(scan_id: str, task: asyncio.Task[None]) -> None:
    async with _streams_lock:
        handle = _streams.get(scan_id)
        if handle is not None:
            handle.task = task


async def iter_sse_events(scan_id: str):
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
