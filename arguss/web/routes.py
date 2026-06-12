"""HTTP routes for Arguss scan modes."""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, File, HTTPException, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, SecretStr
from sse_starlette.sse import EventSourceResponse

from arguss.core.parser import ParserError
from arguss.core.serialization import (
    attach_executive_summary,
    finalize_scan_payload,
)
from arguss.engine.propose import propose_fixes
from arguss.lenses._zizmor_client import ZizmorClientError
from arguss.web.git_clone import GitCloneError
from arguss.web.github_fetch import GitHubFetchError, fetch_repo_inputs
from arguss.web.github_url import InvalidGitHubURLError, parse_github_url
from arguss.web.mode_c_workflow import (
    attach_background_task,
    execute_scan_with_action,
    iter_sse_events,
    register_scan_stream,
    run_scan_background,
)
from arguss.web.zip_safe import ZipExtractionError, extract_workflows_zip

_MAX_LOCKFILE_BYTES = 10 * 1024 * 1024  # 10 MiB
_MAX_WORKFLOWS_ZIP_BYTES = 1 * 1024 * 1024  # 1 MiB
_MAX_PACKAGE_JSON_BYTES = 1 * 1024 * 1024  # 1 MiB
_READ_CHUNK_SIZE = 64 * 1024  # 64 KiB
_INTERNAL_DETAIL = "Internal error during analysis"

_LOG = logging.getLogger(__name__)

router = APIRouter()


class ScanUrlRequest(BaseModel):
    """Request body for /scan/url."""

    url: str = Field(
        ...,
        description="A public GitHub repository URL",
        examples=["https://github.com/expressjs/express"],
    )
    ref: str = Field(
        default="HEAD",
        description=("Branch, tag, or commit SHA to scan. Defaults to the repo's default branch."),
        examples=["main", "4.17.0", "a3b1c0..."],
    )


class ScanWithActionRequest(BaseModel):
    """Request body for /scan/with-action."""

    url: str = Field(
        ...,
        description="A public GitHub repository URL",
        examples=["https://github.com/expressjs/express"],
    )
    pat: SecretStr = Field(
        ...,
        description=("GitHub personal access token with `repo` scope on the target repository"),
    )
    selected_candidate_ids: list[str] | None = None


async def _read_upload_with_limit(
    upload: UploadFile,
    max_bytes: int,
    field_name: str,
) -> bytes:
    """Read an UploadFile up to max_bytes. Raise HTTPException 413 if exceeded."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await upload.read(_READ_CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"{field_name} exceeds maximum size of {max_bytes} bytes",
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _validate_json_bytes(data: bytes, field_name: str) -> None:
    try:
        json.loads(data)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field_name} is not valid JSON",
        ) from exc


def _clone_error_status(exc: GitCloneError) -> int:
    if isinstance(exc.__cause__, subprocess.TimeoutExpired):
        return status.HTTP_504_GATEWAY_TIMEOUT
    if "timed out" in str(exc).lower():
        return status.HTTP_504_GATEWAY_TIMEOUT
    return status.HTTP_404_NOT_FOUND


@router.post(
    "/scan/url",
    status_code=status.HTTP_200_OK,
    summary="Scan a public GitHub repository by URL",
    description=(
        "Fetches repository inputs via the GitHub API, runs vulnerability + "
        "trust + pipeline analysis, generates fix candidates, evaluates each "
        "through the fix-confidence engine. Returns the full proposal report "
        "as JSON. Read-only — no changes are made to the repository."
    ),
)
async def scan_url(request: ScanUrlRequest) -> JSONResponse:
    """Mode A: analyze a public GitHub repo by URL."""
    try:
        parsed = parse_github_url(request.url)
    except InvalidGitHubURLError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    try:
        with tempfile.TemporaryDirectory(prefix="arguss-scan-") as tmp:
            tmp_path = Path(tmp)
            clone_target = tmp_path / parsed.name

            try:
                inputs = await fetch_repo_inputs(
                    owner=parsed.owner,
                    repo=parsed.name,
                    ref=request.ref,
                    dest=clone_target,
                )
            except GitHubFetchError as exc:
                raise HTTPException(
                    status_code=exc.status_code,
                    detail=str(exc),
                ) from exc

            work_tree = inputs.work_tree
            lockfile_path = inputs.lockfile_path

            try:
                report = await run_in_threadpool(
                    propose_fixes,
                    lockfile_path,
                    work_tree,
                    repo_identity=parsed.repo_identity,
                )
            except ParserError as exc:
                _LOG.warning("lockfile parse failed during scan_url: %s", exc)
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=f"Could not parse lockfile: {exc}",
                ) from exc
            except ZizmorClientError as exc:
                _LOG.exception("pipeline snapshot failed during scan_url")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=_INTERNAL_DETAIL,
                ) from exc
            except Exception as exc:
                _LOG.exception("unexpected error during scan_url")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=_INTERNAL_DETAIL,
                ) from exc

            payload = finalize_scan_payload(report, lockfile_path)
            return JSONResponse(
                content=attach_executive_summary(payload),
            )
    except HTTPException:
        raise
    except Exception as exc:
        _LOG.exception("unexpected error in scan_url handler")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_INTERNAL_DETAIL,
        ) from exc


@router.post(
    "/scan/with-action",
    status_code=status.HTTP_200_OK,
    summary="Scan a repo and open PRs for AUTO_MERGE candidates (Mode C)",
    description=(
        "Shallow-clones the public GitHub repository, runs analysis, and "
        "opens pull requests for AUTO_MERGE fix candidates using the provided "
        "PAT. REVIEW_REQUIRED and DECLINE candidates remain in the report but "
        "no PRs are opened for them. The agent does NOT merge any PRs it opens."
    ),
)
async def scan_with_action(request: ScanWithActionRequest) -> JSONResponse:
    """Mode C: analyze and open PRs for in-envelope candidates (blocking JSON)."""
    try:
        result = await execute_scan_with_action(
            url=request.url,
            pat=request.pat.get_secret_value(),
            selected_candidate_ids=request.selected_candidate_ids,
        )
        _LOG.info(
            "mode C pr actions",
            extra={
                "actions_count": len(result.actions),
                "opened": sum(1 for a in result.actions if a.status == "opened"),
                "already_exists": sum(1 for a in result.actions if a.status == "already_exists"),
                "failed": sum(1 for a in result.actions if a.status == "failed"),
                "skipped": sum(1 for a in result.actions if a.status == "skipped"),
            },
        )
        return JSONResponse(content=result.payload)
    except HTTPException:
        raise
    except Exception as exc:
        _LOG.exception("unexpected error in scan_with_action handler")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_INTERNAL_DETAIL,
        ) from exc


class ScanWithActionStartResponse(BaseModel):
    """Response from POST /scan/with-action/start."""

    scan_id: str


@router.post(
    "/scan/with-action/start",
    status_code=status.HTTP_200_OK,
    summary="Start Mode C scan and return a stream id",
)
async def scan_with_action_start(
    request: ScanWithActionRequest,
) -> ScanWithActionStartResponse:
    """Kick off Mode C in the background; consume events via GET stream endpoint."""
    scan_id, _queue = await register_scan_stream()
    task = asyncio.create_task(
        run_scan_background(
            scan_id,
            url=request.url,
            pat=request.pat.get_secret_value(),
            selected_candidate_ids=request.selected_candidate_ids,
        ),
    )
    await attach_background_task(scan_id, task)
    return ScanWithActionStartResponse(scan_id=scan_id)


@router.get(
    "/scan/with-action/stream/{scan_id}",
    summary="SSE stream of Mode C scan progress",
)
async def scan_with_action_stream(scan_id: str) -> EventSourceResponse:
    """Stream progress events for a scan started via /scan/with-action/start."""
    return EventSourceResponse(iter_sse_events(scan_id))


@router.post(
    "/scan/upload",
    status_code=status.HTTP_200_OK,
    summary="Scan from uploaded lockfile (Mode B)",
    description=(
        "Accepts a multipart upload of package-lock.json (required, max 10 MiB) "
        "plus optional .github/workflows/ zip (max 1 MiB) and package.json "
        "(max 1 MiB). Runs vulnerability + trust + pipeline analysis against "
        "the assembled inputs. Returns the full proposal report as JSON."
    ),
)
async def scan_upload(
    lockfile: Annotated[
        UploadFile,
        File(description="package-lock.json (required, max 10 MiB)"),
    ],
    workflows_zip: Annotated[
        UploadFile | None,
        File(description=".github/workflows/ as a zip (optional, max 1 MiB)"),
    ] = None,
    package_json: Annotated[
        UploadFile | None,
        File(description="package.json (optional, max 1 MiB)"),
    ] = None,
) -> JSONResponse:
    """Mode B: analyze uploaded files."""
    lockfile_bytes = await _read_upload_with_limit(
        lockfile,
        _MAX_LOCKFILE_BYTES,
        "lockfile",
    )
    _validate_json_bytes(lockfile_bytes, "lockfile")

    workflows_zip_bytes: bytes | None = None
    if workflows_zip is not None and workflows_zip.filename:
        workflows_zip_bytes = await _read_upload_with_limit(
            workflows_zip,
            _MAX_WORKFLOWS_ZIP_BYTES,
            "workflows_zip",
        )

    package_json_bytes: bytes | None = None
    if package_json is not None and package_json.filename:
        package_json_bytes = await _read_upload_with_limit(
            package_json,
            _MAX_PACKAGE_JSON_BYTES,
            "package_json",
        )
        _validate_json_bytes(package_json_bytes, "package_json")

    try:
        with tempfile.TemporaryDirectory(prefix="arguss-upload-") as tmp:
            tmp_path = Path(tmp)
            lockfile_path = tmp_path / "package-lock.json"
            lockfile_path.write_bytes(lockfile_bytes)

            if package_json_bytes is not None:
                (tmp_path / "package.json").write_bytes(package_json_bytes)

            if workflows_zip_bytes is not None:
                workflows_dir = tmp_path / ".github" / "workflows"
                try:
                    extract_workflows_zip(workflows_zip_bytes, workflows_dir)
                except ZipExtractionError as exc:
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                        detail=str(exc),
                    ) from exc

            try:
                report = await run_in_threadpool(
                    propose_fixes,
                    lockfile_path,
                    tmp_path,
                )
            except ParserError as exc:
                _LOG.warning("lockfile parse failed during scan_upload: %s", exc)
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=f"Could not parse lockfile: {exc}",
                ) from exc
            except ZizmorClientError as exc:
                _LOG.exception("pipeline snapshot failed during scan_upload")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=_INTERNAL_DETAIL,
                ) from exc
            except Exception as exc:
                _LOG.exception("unexpected error during scan_upload")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=_INTERNAL_DETAIL,
                ) from exc

            payload = finalize_scan_payload(report, lockfile_path)
            return JSONResponse(
                content=attach_executive_summary(payload),
            )
    except HTTPException:
        raise
    except Exception as exc:
        _LOG.exception("unexpected error in scan_upload handler")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_INTERNAL_DETAIL,
        ) from exc
