"""HTTP routes for Arguss scan modes."""

from __future__ import annotations

import logging
import subprocess
import tempfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from arguss.core.parser import ParserError
from arguss.core.serialization import proposal_report_payload
from arguss.engine.propose import propose_fixes
from arguss.lenses._zizmor_client import ZizmorClientError
from arguss.web.git_clone import GitCloneError, shallow_clone
from arguss.web.github_url import InvalidGitHubURLError, parse_github_url

_LOG = logging.getLogger(__name__)

router = APIRouter()


class ScanUrlRequest(BaseModel):
    """Request body for /scan/url."""

    url: str = Field(
        ...,
        description="A public GitHub repository URL",
        examples=["https://github.com/expressjs/express"],
    )


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
        "Shallow-clones the repository, runs vulnerability + trust + pipeline "
        "analysis, generates fix candidates, evaluates each through the "
        "fix-confidence engine. Returns the full proposal report as JSON. "
        "Read-only — no changes are made to the repository."
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
                work_tree = shallow_clone(parsed.clone_url, clone_target)
            except GitCloneError as exc:
                code = _clone_error_status(exc)
                detail = (
                    "Clone took too long; repository may be too large"
                    if code == status.HTTP_504_GATEWAY_TIMEOUT
                    else "Repository not found or not accessible"
                )
                raise HTTPException(status_code=code, detail=detail) from exc

            lockfile_path = work_tree / "package-lock.json"
            if not lockfile_path.is_file():
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="Repository does not contain a package-lock.json",
                )

            try:
                report = await run_in_threadpool(
                    propose_fixes,
                    lockfile_path,
                    work_tree,
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
                    detail="Internal error during analysis",
                ) from exc
            except Exception as exc:
                _LOG.exception("unexpected error during scan_url")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Internal error during analysis",
                ) from exc

            return JSONResponse(content=proposal_report_payload(report))
    except HTTPException:
        raise
    except Exception as exc:
        _LOG.exception("unexpected error in scan_url handler")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error during analysis",
        ) from exc
