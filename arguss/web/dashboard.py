"""HTML routes for the Arguss dashboard.

Renders Jinja templates that consume the same engine output as the JSON
endpoints in routes.py. The JSON endpoints stay as the machine API; these
routes are the browser-facing surface.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sse_starlette.sse import EventSourceResponse

from arguss.core.parser import ParserError, parse_lockfile
from arguss.core.serialization import (
    attach_executive_summary,
    proposal_report_payload,
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
from arguss.settings import settings
from arguss.web.error_cards import (
    generic_error_card_context,
    github_fetch_error_card_context,
    osv_unavailable_card_context,
    parser_error_card_context,
    pat_auth_error_card_context,
    report_has_osv_unavailable,
    upload_zip_error_card_context,
)
from arguss.web.github_fetch import GitHubFetchError, fetch_repo_inputs
from arguss.web.github_url import InvalidGitHubURLError, parse_github_url
from arguss.web.mode_c_workflow import (
    attach_background_task,
    execute_scan_with_action,
    iter_sse_events,
    register_scan_stream,
    run_scan_background,
)
from arguss.web.results_context import (
    GLOSSARY_SHORT_DESCRIPTIONS,
    build_results_context,
    finding_confidence_score_tier,
    ordinal,
)
from arguss.web.routes import (
    _INTERNAL_DETAIL,
    _MAX_LOCKFILE_BYTES,
    _MAX_PACKAGE_JSON_BYTES,
    _MAX_WORKFLOWS_ZIP_BYTES,
    _read_upload_with_limit,
    _validate_json_bytes,
)
from arguss.web.wizard import (
    InvalidCandidateSelection,
    classic_pat_create_url,
    fine_grained_pat_create_url,
    parse_repo_owner_name,
    repo_url_from_scan_meta,
    scan_ref_from_scan_meta,
    summarize_selected_candidates,
    validate_selection_against_cached,
)
from arguss.web.wizard_session import (
    STEP_ASSESSMENT_VIEWED,
    STEP_AUTHORIZED,
    STEP_COMPLETED,
    STEP_SELECTED,
    create_session,
    get_or_redirect_wizard_session,
    set_action_id,
    set_last_scan_cookie,
    set_selection,
    set_session_cookie,
    update_step,
)
from arguss.web.zip_safe import ZipExtractionError, extract_workflows_zip

_LOG = logging.getLogger(__name__)
_HEX64 = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _wizard_db_path() -> Path:
    return settings.db_path


router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
# Callable from templates as urgency_tier(score) — not filter pipe syntax.
templates.env.globals["urgency_tier"] = epss_urgency_tier
templates.env.globals["ordinal"] = ordinal
templates.env.globals["GLOSSARY_SHORT_DESCRIPTIONS"] = GLOSSARY_SHORT_DESCRIPTIONS
templates.env.globals["finding_confidence_score_tier"] = finding_confidence_score_tier


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


def _error_card_response(
    request: Request,
    context: dict[str, Any],
    *,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "error.html",
        context,
        status_code=status_code,
    )


def _error_response(request: Request, message: str) -> HTMLResponse:
    return _error_card_response(request, generic_error_card_context(message))


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


def _load_cached_results(scan_hash: str) -> dict[str, Any] | None:
    return get_cached_scan_response(scan_hash)


def _scan_mode(cached: dict[str, Any]) -> str:
    return str((cached.get("scan_meta") or {}).get("mode") or "")


def _wizard_plan_context(
    request: Request,
    cached: dict[str, Any],
    scan_hash: str,
    *,
    selection_error: str | None = None,
) -> dict[str, Any]:
    base = build_results_context(cached, scan_hash)
    return {**base, "request": request, "wizard_plan": True, "selection_error": selection_error}


def _wizard_authorize_context(
    request: Request,
    cached: dict[str, Any],
    scan_hash: str,
    selected_candidate_ids: list[str],
) -> dict[str, Any]:
    scan_meta = cached.get("scan_meta") or {}
    repo_display = str(scan_meta.get("repo_display") or "Unknown repository")
    owner, repo_name = parse_repo_owner_name(scan_meta)
    return {
        "request": request,
        "scan_input_hash": scan_hash,
        "repo_display": repo_display,
        "owner": owner,
        "repo_name": repo_name,
        "ref_display": scan_meta.get("ref", "HEAD"),
        "selected_summaries": summarize_selected_candidates(cached, selected_candidate_ids),
        "selected_candidate_ids": selected_candidate_ids,
        "fine_grained_pat_url": fine_grained_pat_create_url(repo_display=repo_display),
        "classic_pat_url": classic_pat_create_url(),
    }


def _hx_redirect_response(payload: dict[str, Any]) -> Response:
    """Cache scan payload and tell HTMX to navigate to the results page."""
    enriched = attach_executive_summary(payload)
    scan_hash = compute_scan_input_hash(enriched)
    return Response(status_code=200, headers={"HX-Redirect": f"/assessment/{scan_hash}"})


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
    wizard_note: str | None = None,
) -> HTMLResponse:
    prefill_url: str | None = None
    prefill_ref: str | None = ref.strip() if ref and ref.strip() else None
    if demo == "axios":
        prefill_url = "https://github.com/axios/axios"
    return templates.TemplateResponse(
        request,
        "scan.html",
        {"prefill_url": prefill_url, "prefill_ref": prefill_ref, "wizard_note": wizard_note},
    )


@router.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "upload.html")


@router.get("/action", response_class=HTMLResponse)
async def action_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "action.html")


@router.get("/assessment/{scan_hash}", response_class=HTMLResponse)
async def assessment_page(
    request: Request,
    scan_hash: str,
    wizard_note: str | None = None,
) -> HTMLResponse:
    cached = _load_cached_results(scan_hash)
    if cached is None:
        return templates.TemplateResponse(
            request,
            "results_not_found.html",
            {"scan_hash": scan_hash},
            status_code=status.HTTP_404_NOT_FOUND,
        )
    context = build_results_context(cached, scan_hash)
    context["wizard_note"] = wizard_note
    response = templates.TemplateResponse(request, "results.html", context)
    set_last_scan_cookie(response, scan_hash)
    return response


@router.post("/assessment/{scan_hash}/plan")
async def assessment_plan_post(request: Request, scan_hash: str) -> Response:
    cached = _load_cached_results(scan_hash)
    if cached is None:
        return templates.TemplateResponse(
            request,
            "results_not_found.html",
            {"scan_hash": scan_hash},
            status_code=status.HTTP_404_NOT_FOUND,
        )
    if _scan_mode(cached) != "A":
        return RedirectResponse(
            url=f"/assessment/{scan_hash}?wizard_note=upload",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    session = create_session(scan_hash, _wizard_db_path())
    response = RedirectResponse(url="/select", status_code=status.HTTP_303_SEE_OTHER)
    set_session_cookie(response, session.token)
    return response


@router.get("/select", response_class=HTMLResponse)
async def wizard_select_get(request: Request) -> Response:
    guard = get_or_redirect_wizard_session(
        request,
        allowed_steps=(STEP_ASSESSMENT_VIEWED, STEP_SELECTED),
        db_path=_wizard_db_path(),
    )
    if isinstance(guard, RedirectResponse):
        return guard
    session = guard
    cached = _load_cached_results(session.scan_hash)
    if cached is None:
        return templates.TemplateResponse(
            request,
            "results_not_found.html",
            {"scan_hash": session.scan_hash},
            status_code=status.HTTP_404_NOT_FOUND,
        )
    context = _wizard_plan_context(request, cached, session.scan_hash)
    return templates.TemplateResponse(request, "plan.html", context)


@router.post("/select", response_class=HTMLResponse)
async def wizard_select_post(
    request: Request,
    selected_candidate_ids: Annotated[list[str], Form()],
) -> Response:
    guard = get_or_redirect_wizard_session(
        request,
        allowed_steps=(STEP_ASSESSMENT_VIEWED, STEP_SELECTED),
        db_path=_wizard_db_path(),
    )
    if isinstance(guard, RedirectResponse):
        return guard
    session = guard
    cached = _load_cached_results(session.scan_hash)
    if cached is None:
        return templates.TemplateResponse(
            request,
            "results_not_found.html",
            {"scan_hash": session.scan_hash},
            status_code=status.HTTP_404_NOT_FOUND,
        )
    try:
        validate_selection_against_cached(cached, selected_candidate_ids)
    except InvalidCandidateSelection as exc:
        context = _wizard_plan_context(
            request,
            cached,
            session.scan_hash,
            selection_error=str(exc),
        )
        return templates.TemplateResponse(
            request,
            "plan.html",
            context,
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    db = _wizard_db_path()
    set_selection(session.token, selected_candidate_ids, db)
    update_step(session.token, STEP_SELECTED, db)
    return RedirectResponse(url="/authorize", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/authorize", response_class=HTMLResponse)
async def wizard_authorize_get(request: Request) -> Response:
    guard = get_or_redirect_wizard_session(
        request,
        allowed_steps=(STEP_SELECTED, STEP_AUTHORIZED),
        db_path=_wizard_db_path(),
    )
    if isinstance(guard, RedirectResponse):
        return guard
    session = guard
    cached = _load_cached_results(session.scan_hash)
    if cached is None:
        return templates.TemplateResponse(
            request,
            "results_not_found.html",
            {"scan_hash": session.scan_hash},
            status_code=status.HTTP_404_NOT_FOUND,
        )
    context = _wizard_authorize_context(
        request,
        cached,
        session.scan_hash,
        session.selected_candidate_ids,
    )
    return templates.TemplateResponse(request, "authorize.html", context)


@router.post("/authorize", response_class=HTMLResponse)
async def wizard_authorize_post(
    request: Request,
    pat: Annotated[str, Form()] = "",
) -> Response:
    guard = get_or_redirect_wizard_session(
        request,
        allowed_steps=(STEP_SELECTED, STEP_AUTHORIZED),
        db_path=_wizard_db_path(),
    )
    if isinstance(guard, RedirectResponse):
        return guard
    session = guard
    cached = _load_cached_results(session.scan_hash)
    if cached is None:
        return templates.TemplateResponse(
            request,
            "results_not_found.html",
            {"scan_hash": session.scan_hash},
            status_code=status.HTTP_404_NOT_FOUND,
        )
    ids = session.selected_candidate_ids
    try:
        validate_selection_against_cached(cached, ids)
    except InvalidCandidateSelection as exc:
        context = _wizard_plan_context(
            request,
            cached,
            session.scan_hash,
            selection_error=str(exc),
        )
        return templates.TemplateResponse(
            request,
            "plan.html",
            context,
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    if not pat.strip():
        context = _wizard_authorize_context(request, cached, session.scan_hash, ids)
        context["pat_error"] = "PAT is required to begin remediation."
        return templates.TemplateResponse(
            request,
            "authorize.html",
            context,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    scan_meta = cached.get("scan_meta") or {}
    url = repo_url_from_scan_meta(scan_meta)
    ref = scan_ref_from_scan_meta(scan_meta)
    scan_id, _queue = await register_scan_stream()
    task = asyncio.create_task(
        run_scan_background(
            scan_id,
            url=url,
            pat=pat,
            ref=ref,
            selected_candidate_ids=ids,
        ),
    )
    await attach_background_task(scan_id, task)
    db = _wizard_db_path()
    set_action_id(session.token, scan_id, db)
    update_step(session.token, STEP_AUTHORIZED, db)
    return RedirectResponse(
        url=f"/process?scan_id={scan_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/process", response_class=HTMLResponse)
async def wizard_process_page(
    request: Request,
    scan_id: str | None = None,
) -> Response:
    guard = get_or_redirect_wizard_session(
        request,
        allowed_steps=(STEP_AUTHORIZED, STEP_COMPLETED),
        db_path=_wizard_db_path(),
    )
    if isinstance(guard, RedirectResponse):
        return guard
    session = guard
    cached = _load_cached_results(session.scan_hash)
    if cached is None:
        return templates.TemplateResponse(
            request,
            "results_not_found.html",
            {"scan_hash": session.scan_hash},
            status_code=status.HTTP_404_NOT_FOUND,
        )
    db = _wizard_db_path()
    if session.current_step == STEP_AUTHORIZED:
        update_step(session.token, STEP_COMPLETED, db)
    scan_meta = cached.get("scan_meta") or {}
    try:
        github_owner, github_repo = parse_repo_owner_name(scan_meta)
    except ValueError:
        github_owner, github_repo = "", ""
    effective_scan_id = scan_id or session.action_id or ""
    return templates.TemplateResponse(
        request,
        "process.html",
        {
            "scan_input_hash": session.scan_hash,
            "scan_id": effective_scan_id,
            "repo_display": scan_meta.get("repo_display", "Unknown repository"),
            "ref_display": scan_meta.get("ref", "HEAD"),
            "plan_url": "/select",
            "github_owner": github_owner,
            "github_repo": github_repo,
        },
    )


@router.get("/results/{scan_hash}/plan")
@router.get("/results/{scan_hash}/authorize")
@router.get("/results/{scan_hash}/process")
async def wizard_legacy_subroutes(_request: Request, scan_hash: str) -> RedirectResponse:
    del scan_hash
    return RedirectResponse(
        url="/scan?wizard_note=url_moved",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/results/{ident}", response_class=HTMLResponse)
async def results_legacy_redirect(request: Request, ident: str) -> Response:
    if _HEX64.match(ident):
        return RedirectResponse(
            url=f"/assessment/{ident}",
            status_code=status.HTTP_301_MOVED_PERMANENTLY,
        )
    return templates.TemplateResponse(
        request,
        "results_not_found.html",
        {"scan_hash": ident},
        status_code=status.HTTP_404_NOT_FOUND,
    )


@router.post("/dashboard/scan-with-action/start")
async def dashboard_scan_with_action_start(
    url: Annotated[str, Form()],
    ref: Annotated[str, Form()] = "HEAD",
    pat: Annotated[str, Form()] = "",
    selected_candidate_ids: Annotated[list[str] | None, Form()] = None,
) -> JSONResponse:
    """Start Mode C from the dashboard; client connects to SSE stream by scan_id."""
    candidate_ids = selected_candidate_ids or None
    try:
        parse_github_url(url)
    except InvalidGitHubURLError as exc:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": str(exc)},
        )

    if not pat.strip():
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "PAT is required for scan with action"},
        )

    scan_id, _queue = await register_scan_stream()
    task = asyncio.create_task(
        run_scan_background(
            scan_id,
            url=url,
            pat=pat,
            ref=ref,
            selected_candidate_ids=candidate_ids,
        ),
    )
    await attach_background_task(scan_id, task)
    return JSONResponse({"scan_id": scan_id})


@router.get("/dashboard/scan-with-action/stream/{scan_id}")
async def dashboard_scan_with_action_stream(scan_id: str) -> EventSourceResponse:
    """SSE progress stream for a dashboard Mode C scan."""
    return EventSourceResponse(iter_sse_events(scan_id))


@router.post("/dashboard/scan-with-action", response_class=HTMLResponse)
async def dashboard_scan_with_action(
    request: Request,
    url: Annotated[str, Form()],
    ref: Annotated[str, Form()] = "HEAD",
    pat: Annotated[str, Form()] = "",
    selected_candidate_ids: Annotated[list[str] | None, Form()] = None,
) -> Response:
    """Blocking Mode C fallback (HTMX). Prefer /start + SSE stream from the UI."""
    candidate_ids = selected_candidate_ids or None
    try:
        parsed = parse_github_url(url)
    except InvalidGitHubURLError as exc:
        return _error_card_response(
            request,
            github_fetch_error_card_context(str(exc)),
        )

    if not pat.strip():
        return _error_response(request, "PAT is required for scan with action")

    try:
        result = await execute_scan_with_action(
            url=url,
            pat=pat,
            ref=ref,
            selected_candidate_ids=candidate_ids,
        )
        payload = dict(result.payload)
        payload["scan_meta"] = _build_scan_meta(
            repo_display=f"{parsed.owner}/{parsed.name}",
            ref=ref,
            mode="C",
            lockfile_path=Path("/package-lock.json"),
        )
        return _hx_redirect_response(payload)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_403_FORBIDDEN:
            detail = _http_exception_message(exc)
            return _error_card_response(
                request,
                pat_auth_error_card_context(detail),
                status_code=status.HTTP_403_FORBIDDEN,
            )
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            return _error_card_response(
                request,
                pat_auth_error_card_context("Invalid or expired PAT"),
            )
        return _error_response(request, _http_exception_message(exc))
    except Exception:
        _LOG.exception("unexpected error in dashboard_scan_with_action handler")
        return _error_response(request, _INTERNAL_DETAIL)


@router.post("/dashboard/scan", response_class=HTMLResponse)
async def dashboard_scan_url(
    request: Request,
    url: Annotated[str, Form()],
    ref: Annotated[str, Form()] = "HEAD",
) -> Response:
    """Mode A from the dashboard. Returns the results fragment."""
    try:
        parsed = parse_github_url(url)
    except InvalidGitHubURLError as exc:
        return _error_card_response(
            request,
            github_fetch_error_card_context(str(exc)),
        )

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
                return _error_card_response(
                    request,
                    github_fetch_error_card_context(str(exc)),
                )

            work_tree = inputs.work_tree
            lockfile_path = inputs.lockfile_path

            try:
                report = await run_in_threadpool(
                    propose_fixes,
                    lockfile_path,
                    work_tree,
                    repo_identity=parsed.repo_identity,
                )
                if report_has_osv_unavailable(report):
                    return _error_card_response(
                        request,
                        osv_unavailable_card_context(),
                    )
            except ParserError as exc:
                _LOG.warning("lockfile parse failed during dashboard_scan_url: %s", exc)
                return _error_card_response(
                    request,
                    parser_error_card_context(exc),
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
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
) -> Response:
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
                    return _error_card_response(
                        request,
                        upload_zip_error_card_context(str(exc)),
                        status_code=status.HTTP_400_BAD_REQUEST,
                    )

            try:
                report = await run_in_threadpool(
                    propose_fixes,
                    lockfile_path,
                    tmp_path,
                )
                if report_has_osv_unavailable(report):
                    return _error_card_response(
                        request,
                        osv_unavailable_card_context(),
                    )
            except ParserError as exc:
                _LOG.warning("lockfile parse failed during dashboard_scan_upload: %s", exc)
                return _error_card_response(
                    request,
                    parser_error_card_context(exc),
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
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
