"""HTML routes for the Arguss dashboard.

Renders Jinja templates that consume the same engine output as the JSON
endpoints in routes.py. The JSON endpoints stay as the machine API; these
routes are the browser-facing surface.
"""

from __future__ import annotations

import json
import logging
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from arguss.core.models import FixTier
from arguss.core.parser import ParserError, parse_lockfile
from arguss.core.serialization import (
    attach_executive_summary,
    proposal_report_payload,
    proposal_report_with_actions_payload,
)
from arguss.engine.propose import ProposalEntry, ProposalReport, propose_fixes
from arguss.explanations.chat import ChatMessage, answer_question
from arguss.explanations.scan_cache import (
    get_cached_scan_response,
)
from arguss.explanations.scan_cache import (
    scan_input_hash as compute_scan_input_hash,
)
from arguss.lenses._zizmor_client import ZizmorClientError
from arguss.scoring.unified import epss_urgency_tier
from arguss.web.git_clone import GitCloneError, shallow_clone
from arguss.web.github_action import ActionResult, GitHubActionError, open_fix_pr
from arguss.web.github_fetch import GitHubFetchError, fetch_repo_inputs
from arguss.web.github_url import InvalidGitHubURLError, parse_github_url
from arguss.web.results_context import (
    GLOSSARY_SHORT_DESCRIPTIONS,
    build_results_context,
    ordinal,
)
from arguss.web.routes import (
    _INTERNAL_DETAIL,
    _MAX_LOCKFILE_BYTES,
    _MAX_PACKAGE_JSON_BYTES,
    _MAX_WORKFLOWS_ZIP_BYTES,
    _clone_error_status,
    _read_upload_with_limit,
    _validate_json_bytes,
)
from arguss.web.zip_safe import ZipExtractionError, extract_workflows_zip

_LOG = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
# Callable from templates as urgency_tier(score) — not filter pipe syntax.
templates.env.globals["urgency_tier"] = epss_urgency_tier
templates.env.globals["ordinal"] = ordinal
templates.env.globals["GLOSSARY_SHORT_DESCRIPTIONS"] = GLOSSARY_SHORT_DESCRIPTIONS


@dataclass(frozen=True)
class PackageGroup:
    """One row in the grouped results view."""

    name: str
    finding_count: int
    summary_tier: str
    severity_range: str
    trust_subscore: int | None
    max_epss_score: float | None
    has_kev_finding: bool
    kev_finding_count: int
    entries: list[ProposalEntry]


def _sort_entries_by_epss(entries: list[ProposalEntry]) -> list[ProposalEntry]:
    """Sort entries by EPSS score descending; None at end."""

    def sort_key(entry: ProposalEntry) -> tuple[bool, float]:
        epss = entry.candidate.max_epss_score
        return (epss is None, -(epss or 0.0))

    return sorted(entries, key=sort_key)


def group_by_package(report: ProposalReport) -> list[PackageGroup]:
    """Group entries by candidate.package, summarize tier and severity."""
    by_pkg: dict[str, list[ProposalEntry]] = defaultdict(list)
    for entry in report.entries:
        by_pkg[entry.candidate.package].append(entry)

    groups: list[PackageGroup] = []
    for name, entries in by_pkg.items():
        tiers = {e.verdict.tier.value for e in entries}
        summary_tier = next(iter(tiers)) if len(tiers) == 1 else "mixed"
        severities = sorted({e.finding.severity for e in entries})
        severity_range = (
            severities[0] if len(severities) == 1 else f"{severities[0]}–{severities[-1]}"
        )
        trust_sub = entries[0].candidate.trust_subscore if entries else None
        epss_scores = [
            e.candidate.max_epss_score for e in entries if e.candidate.max_epss_score is not None
        ]
        max_epss = max(epss_scores) if epss_scores else None
        has_kev = any(e.finding.is_kev for e in entries)
        kev_count = sum(1 for e in entries if e.finding.is_kev)
        groups.append(
            PackageGroup(
                name=name,
                finding_count=len(entries),
                summary_tier=summary_tier,
                severity_range=severity_range,
                trust_subscore=trust_sub,
                max_epss_score=max_epss,
                has_kev_finding=has_kev,
                kev_finding_count=kev_count,
                entries=_sort_entries_by_epss(entries),
            )
        )

    def _package_sort_key(group: PackageGroup) -> tuple[bool, bool, float, str]:
        return (
            not group.has_kev_finding,
            group.max_epss_score is None,
            -(group.max_epss_score or 0.0),
            group.name.lower(),
        )

    return sorted(groups, key=_package_sort_key)


def _error_response(request: Request, message: str) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "error.html",
        {"message": message},
        status_code=status.HTTP_200_OK,
    )


def _http_exception_message(exc: HTTPException) -> str:
    detail = exc.detail
    if isinstance(detail, str):
        return detail
    return str(detail)


def _dep_counts(lockfile_path: Path) -> dict[str, int]:
    try:
        deps = parse_lockfile(lockfile_path)
    except Exception:
        return {"direct": 0, "transitive": 0}
    return {
        "direct": sum(1 for dep in deps if dep.direct),
        "transitive": sum(1 for dep in deps if not dep.direct),
    }


def _build_scan_meta(
    *,
    repo_display: str,
    ref: str,
    mode: str,
    lockfile_path: Path,
) -> dict[str, Any]:
    return {
        "repo_display": repo_display,
        "ref": ref or "HEAD",
        "mode": mode,
        "completed_at": datetime.now(UTC).isoformat(),
        "dep_counts": _dep_counts(lockfile_path),
    }


def _hx_redirect_response(payload: dict[str, Any]) -> Response:
    """Cache scan payload and tell HTMX to navigate to the results page."""
    enriched = attach_executive_summary(payload)
    scan_hash = compute_scan_input_hash(enriched)
    return Response(status_code=200, headers={"HX-Redirect": f"/results/{scan_hash}"})


@router.get("/", response_class=HTMLResponse)
async def home(request: Request) -> HTMLResponse:
    """Marketing home page."""
    return templates.TemplateResponse(request, "index.html")


@router.get("/how-it-works", response_class=HTMLResponse)
async def how_it_works(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "how_it_works.html")


@router.get("/about", response_class=HTMLResponse)
async def about(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "about.html")


@router.get("/scan", response_class=HTMLResponse)
async def scan_page(
    request: Request,
    demo: str | None = None,
    ref: str | None = None,
) -> HTMLResponse:
    prefill_url: str | None = None
    prefill_ref: str | None = ref.strip() if ref and ref.strip() else None
    if demo == "axios":
        prefill_url = "https://github.com/axios/axios"
    return templates.TemplateResponse(
        request,
        "scan.html",
        {"prefill_url": prefill_url, "prefill_ref": prefill_ref},
    )


@router.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "upload.html")


@router.get("/action", response_class=HTMLResponse)
async def action_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "action.html")


@router.get("/results/{scan_hash}", response_class=HTMLResponse)
async def results_page(request: Request, scan_hash: str) -> HTMLResponse:
    """Render the results page for a previously cached scan."""
    cached = get_cached_scan_response(scan_hash)
    if cached is None:
        return templates.TemplateResponse(
            request,
            "results_not_found.html",
            {"scan_hash": scan_hash},
            status_code=status.HTTP_404_NOT_FOUND,
        )
    context = build_results_context(cached, scan_hash)
    return templates.TemplateResponse(request, "results.html", context)


@router.post("/dashboard/scan-with-action", response_class=HTMLResponse)
async def dashboard_scan_with_action(
    request: Request,
    url: Annotated[str, Form()],
    ref: Annotated[str, Form()] = "HEAD",
    pat: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Mode C from the dashboard. Returns results + actions section."""
    try:
        parsed = parse_github_url(url)
    except InvalidGitHubURLError as exc:
        return _error_response(request, str(exc))

    if not pat.strip():
        return _error_response(request, "PAT is required for scan with action")

    try:
        with tempfile.TemporaryDirectory(prefix="arguss-scan-action-") as tmp:
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
                return _error_response(request, detail)

            lockfile_path = work_tree / "package-lock.json"
            if not lockfile_path.is_file():
                return _error_response(
                    request,
                    "Repository does not contain a package-lock.json",
                )

            try:
                report = await run_in_threadpool(
                    propose_fixes,
                    lockfile_path,
                    work_tree,
                )
            except ParserError as exc:
                _LOG.warning(
                    "lockfile parse failed during dashboard_scan_with_action: %s",
                    exc,
                )
                return _error_response(request, f"Could not parse lockfile: {exc}")
            except ZizmorClientError:
                _LOG.exception("pipeline snapshot failed during dashboard_scan_with_action")
                return _error_response(request, _INTERNAL_DETAIL)
            except Exception:
                _LOG.exception("unexpected error during dashboard_scan_with_action analysis")
                return _error_response(request, _INTERNAL_DETAIL)

            actions: list[ActionResult] = []
            for entry in report.entries:
                if entry.verdict.tier is not FixTier.AUTO_MERGE:
                    continue
                try:
                    result = await run_in_threadpool(
                        open_fix_pr,
                        entry.candidate,
                        entry.verdict,
                        entry.finding,
                        work_tree,
                        parsed.owner,
                        parsed.name,
                        pat,
                    )
                except GitHubActionError as exc:
                    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
                        return _error_response(request, "Invalid or expired PAT")
                    if exc.status_code == status.HTTP_403_FORBIDDEN:
                        return _error_response(
                            request,
                            "PAT lacks repo scope on this repository",
                        )
                    result = ActionResult(
                        candidate_id=entry.candidate.candidate_id,
                        status="failed",
                        pr_url=None,
                        pr_number=None,
                        reason=str(exc),
                    )
                actions.append(result)

            payload = proposal_report_with_actions_payload(report, actions)
            payload["scan_meta"] = _build_scan_meta(
                repo_display=f"{parsed.owner}/{parsed.name}",
                ref=ref,
                mode="C",
                lockfile_path=lockfile_path,
            )
            return _hx_redirect_response(payload)
    except HTTPException as exc:
        return _error_response(request, _http_exception_message(exc))
    except Exception:
        _LOG.exception("unexpected error in dashboard_scan_with_action handler")
        return _error_response(request, _INTERNAL_DETAIL)


@router.post("/dashboard/scan", response_class=HTMLResponse)
async def dashboard_scan_url(
    request: Request,
    url: Annotated[str, Form()],
    ref: Annotated[str, Form()] = "HEAD",
) -> HTMLResponse:
    """Mode A from the dashboard. Returns the results fragment."""
    try:
        parsed = parse_github_url(url)
    except InvalidGitHubURLError as exc:
        return _error_response(request, str(exc))

    try:
        with tempfile.TemporaryDirectory(prefix="arguss-scan-") as tmp:
            tmp_path = Path(tmp)
            clone_target = tmp_path / parsed.name

            try:
                inputs = await fetch_repo_inputs(
                    owner=parsed.owner,
                    repo=parsed.name,
                    ref=ref,
                    dest=clone_target,
                )
            except GitHubFetchError as exc:
                return _error_response(request, str(exc))

            work_tree = inputs.work_tree
            lockfile_path = inputs.lockfile_path

            try:
                report = await run_in_threadpool(
                    propose_fixes,
                    lockfile_path,
                    work_tree,
                )
            except ParserError as exc:
                _LOG.warning("lockfile parse failed during dashboard_scan_url: %s", exc)
                return _error_response(request, f"Could not parse lockfile: {exc}")
            except ZizmorClientError:
                _LOG.exception("pipeline snapshot failed during dashboard_scan_url")
                return _error_response(request, _INTERNAL_DETAIL)
            except Exception:
                _LOG.exception("unexpected error during dashboard_scan_url")
                return _error_response(request, _INTERNAL_DETAIL)

            payload = proposal_report_payload(report)
            payload["scan_meta"] = _build_scan_meta(
                repo_display=f"{parsed.owner}/{parsed.name}",
                ref=ref,
                mode="A",
                lockfile_path=lockfile_path,
            )
            return _hx_redirect_response(payload)
    except HTTPException as exc:
        return _error_response(request, _http_exception_message(exc))
    except Exception:
        _LOG.exception("unexpected error in dashboard_scan_url handler")
        return _error_response(request, _INTERNAL_DETAIL)


@router.post("/dashboard/upload", response_class=HTMLResponse)
async def dashboard_scan_upload(
    request: Request,
    lockfile: Annotated[UploadFile, File()],
    workflows_zip: Annotated[UploadFile | None, File()] = None,
    package_json: Annotated[UploadFile | None, File()] = None,
) -> HTMLResponse:
    """Mode B from the dashboard. Returns the results fragment."""
    try:
        lockfile_bytes = await _read_upload_with_limit(
            lockfile,
            _MAX_LOCKFILE_BYTES,
            "lockfile",
        )
        _validate_json_bytes(lockfile_bytes, "lockfile")
    except HTTPException as exc:
        return _error_response(request, _http_exception_message(exc))

    workflows_zip_bytes: bytes | None = None
    if workflows_zip is not None and workflows_zip.filename:
        try:
            workflows_zip_bytes = await _read_upload_with_limit(
                workflows_zip,
                _MAX_WORKFLOWS_ZIP_BYTES,
                "workflows_zip",
            )
        except HTTPException as exc:
            return _error_response(request, _http_exception_message(exc))

    package_json_bytes: bytes | None = None
    if package_json is not None and package_json.filename:
        try:
            package_json_bytes = await _read_upload_with_limit(
                package_json,
                _MAX_PACKAGE_JSON_BYTES,
                "package_json",
            )
            _validate_json_bytes(package_json_bytes, "package_json")
        except HTTPException as exc:
            return _error_response(request, _http_exception_message(exc))

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
                    return _error_response(request, str(exc))

            try:
                report = await run_in_threadpool(
                    propose_fixes,
                    lockfile_path,
                    tmp_path,
                )
            except ParserError as exc:
                _LOG.warning("lockfile parse failed during dashboard_scan_upload: %s", exc)
                return _error_response(request, f"Could not parse lockfile: {exc}")
            except ZizmorClientError:
                _LOG.exception("pipeline snapshot failed during dashboard_scan_upload")
                return _error_response(request, _INTERNAL_DETAIL)
            except Exception:
                _LOG.exception("unexpected error during dashboard_scan_upload")
                return _error_response(request, _INTERNAL_DETAIL)

            payload = proposal_report_payload(report)
            payload["scan_meta"] = _build_scan_meta(
                repo_display="Uploaded lockfile",
                ref="—",
                mode="B",
                lockfile_path=lockfile_path,
            )
            return _hx_redirect_response(payload)
    except HTTPException as exc:
        return _error_response(request, _http_exception_message(exc))
    except Exception:
        _LOG.exception("unexpected error in dashboard_scan_upload handler")
        return _error_response(request, _INTERNAL_DETAIL)


@router.post("/dashboard/chat", response_class=HTMLResponse)
async def dashboard_chat(
    request: Request,
    scan_input_hash: Annotated[str, Form()],
    history_json: Annotated[str, Form()] = "[]",
    question: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Answer a chat question about a previously-run scan."""
    try:
        history_data = json.loads(history_json)
        history = [ChatMessage(**m) for m in history_data]
    except (json.JSONDecodeError, ValidationError, TypeError):
        history = []

    history = history[-20:]

    answer = await run_in_threadpool(
        answer_question,
        scan_input_hash,
        history,
        question,
    )

    if answer is None:
        return templates.TemplateResponse(
            request,
            "partials/_chat_error.html",
            {
                "message": "Chat is currently unavailable. Try again in a moment.",
            },
        )

    new_history = history + [
        ChatMessage(role="user", content=question),
        ChatMessage(role="assistant", content=answer),
    ]

    return templates.TemplateResponse(
        request,
        "partials/_chat_turn.html",
        {
            "question": question,
            "answer": answer,
            "new_history_json": json.dumps([m.model_dump() for m in new_history]),
            "scan_input_hash": scan_input_hash,
        },
    )
