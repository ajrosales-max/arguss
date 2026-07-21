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
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sse_starlette.sse import EventSourceResponse

from arguss.core.cache import Cache, get_connection, init_db
from arguss.core.parser import ParserError
from arguss.core.sbom import generate_sbom
from arguss.core.serialization import (
    attach_executive_summary,
    finalize_scan_payload,
)
from arguss.data.npm_incidents import load_npm_incidents, match_package_to_incidents
from arguss.engine.explanation import (
    FindingExplainSections,
    explain_finding_verdict_for_select,
    explain_finding_verdict_to_human,
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
from arguss.scoring.unified import epss_urgency_tier, is_high_epss
from arguss.settings import settings
from arguss.web.action_records import (
    ActionRecord,
    create_action_record,
    distinct_failure_reasons,
    load_action_record,
    load_scan_summary_for_action_page,
)
from arguss.web.action_runs import (
    candidate_state_badge_class,
    candidate_state_label,
    candidate_state_secondary_detail,
    is_action_run_terminal,
    load_action_run,
    load_action_run_by_wizard_action_id,
)
from arguss.web.error_cards import (
    generic_error_card_context,
    github_fetch_error_card_context,
    osv_unavailable_card_context,
    parser_error_card_context,
    report_has_osv_unavailable,
    scan_rate_limited_card_context,
    upload_zip_error_card_context,
    wizard_remediation_failed_card_context,
)
from arguss.web.github_fetch import GitHubFetchError, fetch_repo_inputs
from arguss.web.github_install import session_installation_id
from arguss.web.github_url import (
    InvalidGitHubURLError,
    InvalidGitRefError,
    parse_github_url,
    validate_git_ref,
)
from arguss.web.mode_c_workflow import (
    attach_background_task,
    execute_scan_with_action,
    get_scan_stream_queue,
    iter_sse_events,
    register_scan_stream,
    run_scan_background,
)
from arguss.web.observatory_seed import (
    load_observatory_report,
    load_observatory_seed,
)
from arguss.web.process_hydration import build_process_hydration
from arguss.web.results_context import (
    GLOSSARY_SHORT_DESCRIPTIONS,
    build_results_context,
    finding_confidence_score_tier,
    lookup_cached_entry_by_finding_id,
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
from arguss.web.sbom_export import (
    deps_from_cached,
    project_identity_for_sbom,
    sbom_download_filename,
)
from arguss.web.scan_inputs import ScanInputs, load_scan_inputs, save_scan_inputs
from arguss.web.scan_rate_limit import (
    ScanRateLimitDenial,
    check_scan_rate_limit,
    scan_rate_limit_http_exception,
)
from arguss.web.url_scan import build_scan_meta, run_scan_from_url
from arguss.web.wizard import (
    InvalidCandidateSelection,
    parse_repo_owner_name,
    repo_url_from_scan_meta,
    scan_ref_from_scan_meta,
    summarize_selected_candidates,
    validate_auto_merge_subset,
    validate_selection_against_cached,
)
from arguss.web.wizard_session import (
    STEP_ASSESSMENT_VIEWED,
    STEP_AUTHORIZE_FAILED,
    STEP_AUTHORIZED,
    STEP_COMPLETED,
    STEP_SELECTED,
    WIZARD_SESSION_COOKIE,
    WizardSession,
    create_session,
    expired_wizard_redirect,
    get_or_redirect_wizard_session,
    load_session,
    set_action_id,
    set_last_scan_cookie,
    set_selection,
    set_session_cookie,
    update_step,
)
from arguss.web.zip_safe import ZipExtractionError, extract_workflows_zip

_LOG = logging.getLogger(__name__)

# Browser Mode C enact uses the OAuth-verified session id; missing → connect first.
_GITHUB_INSTALL_URL = "/github/install"

_FINDING_EXPLAIN_SOURCE = "finding_explain"
_FINDING_EXPLAIN_SELECT_SOURCE = "finding_explain_select"
_FINDING_EXPLAIN_TTL_SECONDS = 86400


def _get_explanation_cache() -> Cache:
    conn = get_connection(settings.db_path)
    init_db(conn)
    return Cache(conn)


def _finding_explain_cache_key(scan_hash: str, finding_id: str) -> str:
    return f"{scan_hash}:{finding_id}"


def _wants_version_risks_section(include_version_risks: str | None) -> bool:
    return (include_version_risks or "").strip().lower() in {"1", "true", "yes", "on"}


def _select_explain_cache_payload(sections: FindingExplainSections) -> str:
    return json.dumps({"verdict": sections.verdict, "version_risks": sections.version_risks})


def _parse_select_explain_cache(cached: str) -> FindingExplainSections | None:
    try:
        payload = json.loads(cached)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    verdict = payload.get("verdict")
    version_risks = payload.get("version_risks")
    if not isinstance(verdict, str) or not isinstance(version_risks, str):
        return None
    if not verdict.strip() or not version_risks.strip():
        return None
    return FindingExplainSections(verdict=verdict.strip(), version_risks=version_risks.strip())


def _render_finding_explain_panel(
    request: Request,
    *,
    explanation: str | None,
    version_risks: str | None = None,
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "partials/_finding_explain_panel.html",
        {"explanation": explanation, "version_risks": version_risks},
    )


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
templates.env.globals["is_high_epss"] = is_high_epss
templates.env.globals["ordinal"] = ordinal
templates.env.globals["GLOSSARY_SHORT_DESCRIPTIONS"] = GLOSSARY_SHORT_DESCRIPTIONS
templates.env.globals["finding_confidence_score_tier"] = finding_confidence_score_tier
templates.env.globals["allow_decline_override"] = lambda: settings.allow_decline_override
templates.env.globals["candidate_state_badge_class"] = candidate_state_badge_class
templates.env.globals["candidate_state_label"] = candidate_state_label
templates.env.globals["candidate_state_secondary_detail"] = candidate_state_secondary_detail
templates.env.globals["is_action_run_terminal"] = is_action_run_terminal


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
    headers: dict[str, str] | None = None,
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "error.html",
        context,
        status_code=status_code,
        headers=headers,
    )


def _scan_rate_limited_response(
    request: Request,
    denial: ScanRateLimitDenial,
) -> HTMLResponse:
    """429 error card for browser/HTMX scan triggers (legible, not a traceback)."""
    return _error_card_response(
        request,
        scan_rate_limited_card_context(denial.detail),
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        headers={"Retry-After": str(denial.retry_after_seconds)},
    )


def _error_response(request: Request, message: str) -> HTMLResponse:
    return _error_card_response(request, generic_error_card_context(message))


def _http_exception_message(exc: HTTPException) -> str:
    detail = exc.detail
    if isinstance(detail, str):
        return detail
    return str(detail)


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
    session: WizardSession | None = None,
    submitted_auto_merge_ids: list[str] | None = None,
) -> dict[str, Any]:
    base = build_results_context(cached, scan_hash)
    precheck = submitted_auto_merge_ids
    if precheck is None and session is not None and session.current_step == STEP_SELECTED:
        precheck = session.auto_merge_candidate_ids
    return {
        **base,
        "request": request,
        "wizard_plan": True,
        "selection_error": selection_error,
        "auto_merge_candidate_ids": precheck,
    }


def _wizard_authorize_context(
    request: Request,
    cached: dict[str, Any],
    scan_hash: str,
    selected_candidate_ids: list[str],
    auto_merge_candidate_ids: list[str],
) -> dict[str, Any]:
    scan_meta = cached.get("scan_meta") or {}
    repo_display = str(scan_meta.get("repo_display") or "Unknown repository")
    owner, repo_name = parse_repo_owner_name(scan_meta)
    installation_id = _session_installation_id(request)
    return {
        "request": request,
        "scan_input_hash": scan_hash,
        "repo_display": repo_display,
        "owner": owner,
        "repo_name": repo_name,
        "ref_display": scan_meta.get("ref", "HEAD"),
        "selected_summaries": summarize_selected_candidates(
            cached,
            selected_candidate_ids,
            auto_merge_candidate_ids,
        ),
        "selected_candidate_ids": selected_candidate_ids,
        "auto_merge_candidate_ids": auto_merge_candidate_ids,
        "github_connected": installation_id is not None,
        "github_installation_id": installation_id,
    }


def _session_installation_id(request: Request) -> int | None:
    """Return the OAuth-verified installation id from the signed session, if any.

    Browser Mode C enact reads only this value (not a request/form field).
    Shared with the JSON Mode C endpoints via github_install.
    """
    return session_installation_id(request)


def _redirect_to_github_install() -> RedirectResponse:
    """Send the browser to connect the GitHub App before Mode C enact."""
    return RedirectResponse(
        url=_GITHUB_INSTALL_URL,
        status_code=status.HTTP_303_SEE_OTHER,
    )


def _linked_action_record(session: WizardSession, db: Path) -> ActionRecord | None:
    if not session.action_id:
        return None
    return load_action_record(session.action_id, db)


def _authorize_access_redirect(
    request: Request, session: WizardSession, db: Path
) -> RedirectResponse | None:
    if session.current_step == STEP_AUTHORIZED:
        record = _linked_action_record(session, db)
        if record is None:
            return expired_wizard_redirect(request)
        if record.status == "pending":
            return RedirectResponse(
                "/process?wizard_note=action_in_progress",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        if session.action_id:
            return RedirectResponse(
                f"/results/{session.action_id}?wizard_note=already_completed",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        return expired_wizard_redirect(request)
    if session.current_step == STEP_COMPLETED:
        if not session.action_id or _linked_action_record(session, db) is None:
            return expired_wizard_redirect(request)
        return RedirectResponse(
            f"/results/{session.action_id}?wizard_note=already_completed",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    if session.current_step not in (STEP_SELECTED, STEP_AUTHORIZE_FAILED):
        return expired_wizard_redirect(request)
    return None


def _load_wizard_session_or_expired(request: Request, db: Path) -> WizardSession | RedirectResponse:
    token = request.cookies.get(WIZARD_SESSION_COOKIE)
    if not token:
        return expired_wizard_redirect(request)
    session = load_session(token, db)
    if session is None:
        return expired_wizard_redirect(request)
    return session


def _render_expired_page(
    request: Request,
    scan_hash: str,
    *,
    kind: str = "unknown",
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "results_not_found.html",
        {"scan_hash": scan_hash, "kind": kind},
        status_code=status.HTTP_404_NOT_FOUND,
    )


async def _rescan_from_inputs(inputs: ScanInputs) -> dict[str, Any]:
    return await run_scan_from_url(
        inputs.url,
        ref=inputs.ref or "HEAD",
        mode=inputs.mode,
        db_path=_wizard_db_path(),
        persist_inputs=True,
    )


def _hx_redirect_response(
    payload: dict[str, Any],
    *,
    persist_url: str | None = None,
    persist_ref: str | None = None,
) -> Response:
    """Cache scan payload and tell HTMX to navigate to the results page."""
    enriched = attach_executive_summary(payload)
    scan_hash = compute_scan_input_hash(enriched)
    mode = str((payload.get("scan_meta") or {}).get("mode") or "")
    if persist_url is not None and mode in ("A", "C"):
        save_scan_inputs(scan_hash, mode, persist_url, persist_ref, _wizard_db_path())
    return Response(status_code=200, headers={"HX-Redirect": f"/assessment/{scan_hash}"})


@router.get("/why-arguss", response_class=HTMLResponse)
async def why_arguss(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "why_arguss.html", {})


@router.get("/", response_class=HTMLResponse)
async def home(request: Request) -> HTMLResponse:
    """Marketing home page."""
    return templates.TemplateResponse(request, "index.html", _observatory_context())


@router.get("/how-it-works", response_class=HTMLResponse)
async def how_it_works(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "how_it_works.html")


def _observatory_context() -> dict[str, Any]:
    data = load_observatory_seed()
    return {
        "scans": data.scans,
        "stats": data.stats,
        "last_refreshed": data.last_refreshed,
        "total_projects": data.total_projects,
    }


@router.get("/about", response_class=HTMLResponse)
async def about(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "about.html")


TopPackageStatus = Literal["clear", "vulnerable", "malware", "unknown"]


@dataclass(frozen=True)
class TopPackageRow:
    rank: int
    name: str
    historical_advisory_count: int
    historical_advisory_ids: list[str]
    latest_version: str | None
    latest_vulnerable: int | None
    latest_advisories: list[dict[str, Any]]
    swept_at: str
    previously_vulnerable_version: str | None
    patched_advisory_ids: list[str]
    max_epss: float | None
    previously_vulnerable_advisories: list[dict[str, Any]]
    status: TopPackageStatus
    has_malware_history: bool
    malware_incident_label: str | None
    historical_advisory_summaries: list[dict[str, Any]]
    last_advisory_date: str | None
    last_advisory_date_display: str | None
    severity_chips: list[dict[str, Any]] | None
    advisory_history: list[dict[str, Any]] | None
    linked_incident_id: str | None
    linked_incident_chip: str | None


def _is_malware_osv_record(record: dict[str, Any]) -> bool:
    advisory_id = record.get("id")
    if isinstance(advisory_id, str) and advisory_id.startswith("MAL-"):
        return True
    database_specific = record.get("database_specific")
    if isinstance(database_specific, dict):
        return "malicious-packages-origins" in database_specific
    return False


def _latest_advisories_include_malware(latest_advisories: list[dict[str, Any]]) -> bool:
    return any(_is_malware_osv_record(record) for record in latest_advisories)


def derive_top_package_status(
    latest_vulnerable: int | None,
    latest_advisories: list[dict[str, Any]],
) -> TopPackageStatus:
    if _latest_advisories_include_malware(latest_advisories):
        return "malware"
    if latest_vulnerable == 1:
        return "vulnerable"
    if latest_vulnerable == 0:
        return "clear"
    return "unknown"


def derive_malware_incidents(
    summaries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Malware advisories from historical_advisory_summaries (with published dates).

    Single source for incident badge presence/date, Malware history filter, and
    (via callers) header 12-month malware counts. Peak-based ``is_malware`` is
    not consulted.
    """
    return [item for item in summaries if item.get("is_malware")]


def derive_malware_incident_label(
    malware_incidents: list[dict[str, Any]],
    latest_status: TopPackageStatus,
) -> str | None:
    """Badge label for historical malware; suppressed when latest status is malware."""
    if not malware_incidents or latest_status == "malware":
        return None
    incident_date = _malware_incident_date_from_summaries(malware_incidents)
    if incident_date is None:
        return "Malware incident"
    return f"Malware incident · {incident_date.strftime('%b %Y')}"


def format_last_advisory_date(raw: str | None) -> str | None:
    """Human-readable last-advisory date; None when absent/unparseable."""
    if not raw or not str(raw).strip():
        return None
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%b %d, %Y")


def _normalize_summary_severity(raw: object) -> str | None:
    if not isinstance(raw, str):
        return None
    key = raw.strip().lower()
    if key == "medium":
        key = "moderate"
    if key in ("critical", "high", "moderate", "low"):
        return key
    return None


def _severity_chip_css(label: str) -> str:
    css = "medium" if label == "moderate" else label
    return f"finding-severity-{css}"


def derive_advisory_severity_chips(
    summaries: list[dict[str, Any]],
) -> list[dict[str, Any]] | None:
    """Aggregate severity/malware chips from historical summaries.

    Returns ``None`` when summaries are absent (NULL / empty) so the UI can fall
    back without implying a verified-empty severity breakdown.
    """
    if not summaries:
        return None

    severity_counts: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "moderate": 0,
        "low": 0,
    }
    malware_count = 0
    for item in summaries:
        if item.get("is_malware"):
            malware_count += 1
            continue
        key = _normalize_summary_severity(item.get("severity"))
        if key is not None:
            severity_counts[key] += 1

    chips: list[dict[str, Any]] = []
    for label in ("critical", "high", "moderate", "low"):
        count = severity_counts[label]
        if count:
            chips.append(
                {
                    "kind": "severity",
                    "label": label,
                    "count": count,
                    "css_class": _severity_chip_css(label),
                }
            )
    if malware_count:
        chips.append(
            {
                "kind": "malware",
                "label": "malware",
                "count": malware_count,
                "css_class": "tp-chip-malware",
            }
        )
    return chips


def _published_sort_key(published: object) -> datetime:
    """Newest-first sort key; unparseable/missing dates sort as oldest."""
    if not isinstance(published, str) or not published.strip():
        return datetime.min.replace(tzinfo=UTC)
    try:
        dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def derive_advisory_history(
    summaries: list[dict[str, Any]],
    *,
    peak_affected_ids: list[str],
) -> list[dict[str, Any]] | None:
    """Full advisory history for the expand panel, newest first.

    Returns ``None`` when summaries are absent so the template can fall back to
    peak-affected / latest rendering. Entries come from the same summary list
    as severity chips.
    """
    if not summaries:
        return None

    peak_ids = {str(adv_id) for adv_id in peak_affected_ids}
    entries: list[dict[str, Any]] = []
    for item in summaries:
        raw_id = item.get("id")
        adv_id = str(raw_id) if raw_id is not None else "—"
        is_malware = bool(item.get("is_malware"))
        severity = None if is_malware else _normalize_summary_severity(item.get("severity"))
        published = item.get("published")
        published_str = published if isinstance(published, str) else None
        summary = item.get("summary")
        entries.append(
            {
                "id": adv_id,
                "osv_url": f"https://osv.dev/vulnerability/{adv_id}" if adv_id != "—" else None,
                "summary": summary if isinstance(summary, str) else "",
                "published": published_str,
                "published_display": format_last_advisory_date(published_str),
                "is_malware": is_malware,
                "severity": severity,
                "severity_css_class": _severity_chip_css(severity) if severity else None,
                "peak_affected": adv_id in peak_ids,
            }
        )

    entries.sort(key=lambda e: _published_sort_key(e.get("published")), reverse=True)
    return entries


def derive_top_packages_header_counts(
    packages: list[TopPackageRow],
    *,
    now: datetime | None = None,
) -> dict[str, int | None]:
    """Derive banner counts from the same row objects the table renders.

    ``malware_last_12mo`` is ``None`` when no row has populated summaries (omit
    from the banner rather than claiming zero incidents).
    """
    clock = now if now is not None else datetime.now(UTC)
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=UTC)

    currently_vulnerable = 0
    clear = 0
    unknown = 0
    malware_last_12mo = 0
    any_summaries_populated = False
    cutoff = clock - timedelta(days=365)

    for pkg in packages:
        if pkg.latest_vulnerable == 1:
            currently_vulnerable += 1
        elif pkg.latest_vulnerable == 0:
            clear += 1
        else:
            unknown += 1

        if pkg.historical_advisory_summaries:
            any_summaries_populated = True
            if _package_has_recent_malware(pkg.historical_advisory_summaries, cutoff):
                malware_last_12mo += 1

    return {
        "currently_vulnerable": currently_vulnerable,
        "clear": clear,
        "unknown": unknown,
        "malware_last_12mo": malware_last_12mo if any_summaries_populated else None,
    }


def _package_has_recent_malware(
    summaries: list[dict[str, Any]],
    cutoff: datetime,
) -> bool:
    for item in derive_malware_incidents(summaries):
        published = item.get("published")
        if not isinstance(published, str) or not published.strip():
            continue
        try:
            dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        if dt >= cutoff:
            return True
    return False


def _malware_incident_date_from_summaries(
    summaries: list[dict[str, Any]],
) -> datetime | None:
    """Most recent published date among malware advisories; None if absent/unparseable."""
    best: datetime | None = None
    for item in derive_malware_incidents(summaries):
        published = item.get("published")
        if not isinstance(published, str) or not published.strip():
            continue
        try:
            dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        if best is None or dt > best:
            best = dt
    return best


def _format_swept_at(raw: str | None) -> str | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return raw
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%b %d, %Y · %H:%M UTC")


def _parse_json_string_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed]


def _parse_json_advisories(raw: str | None) -> list[dict[str, Any]]:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def _top_packages_context(
    db_path: Path | None = None,
    *,
    incidents_path: Path | None = None,
) -> dict[str, Any]:
    conn = get_connection(db_path or settings.db_path)
    init_db(conn)
    try:
        rows = conn.execute(
            "SELECT rank, name, historical_advisory_count, historical_advisory_ids, "
            "latest_version, latest_vulnerable, latest_advisories, swept_at, "
            "previously_vulnerable_version, patched_advisory_ids, max_epss, "
            "previously_vulnerable_advisories, historical_advisory_summaries, "
            "last_advisory_date "
            "FROM top_packages ORDER BY rank ASC"
        ).fetchall()
    finally:
        conn.close()

    curated_incidents = load_npm_incidents(incidents_path)
    # Draft rows + incident_id per package; chip labels need matched counts.
    drafts: list[dict[str, Any]] = []
    incident_matched_names: dict[str, set[str]] = defaultdict(set)

    for row in rows:
        max_epss_raw = row["max_epss"]
        latest_advisories = _parse_json_advisories(row["latest_advisories"])
        latest_vulnerable = row["latest_vulnerable"]
        status = derive_top_package_status(latest_vulnerable, latest_advisories)
        historical_advisory_summaries = _parse_json_advisories(row["historical_advisory_summaries"])
        malware_incidents = derive_malware_incidents(historical_advisory_summaries)
        has_malware_history = bool(malware_incidents)
        last_advisory_date = row["last_advisory_date"]
        if not isinstance(last_advisory_date, str) or not last_advisory_date.strip():
            last_advisory_date = None
        malware_incident_label = derive_malware_incident_label(malware_incidents, status)
        patched_advisory_ids = _parse_json_string_list(row["patched_advisory_ids"])
        previously_vulnerable_advisories = _parse_json_advisories(
            row["previously_vulnerable_advisories"]
        )
        peak_affected_ids = list(
            dict.fromkeys(
                [
                    *patched_advisory_ids,
                    *[
                        str(adv["id"])
                        for adv in previously_vulnerable_advisories
                        if adv.get("id") is not None
                    ],
                ]
            )
        )
        package_name = str(row["name"])
        matches = match_package_to_incidents(package_name, malware_incidents, curated_incidents)
        linked_incident = matches[0].incident if matches else None
        if linked_incident is not None:
            incident_matched_names[linked_incident.incident_id].add(package_name)

        drafts.append(
            {
                "rank": int(row["rank"]),
                "name": package_name,
                "historical_advisory_count": int(row["historical_advisory_count"]),
                "historical_advisory_ids": _parse_json_string_list(row["historical_advisory_ids"]),
                "latest_version": row["latest_version"],
                "latest_vulnerable": latest_vulnerable,
                "latest_advisories": latest_advisories,
                "swept_at": str(row["swept_at"]),
                "previously_vulnerable_version": row["previously_vulnerable_version"],
                "patched_advisory_ids": patched_advisory_ids,
                "max_epss": float(max_epss_raw) if max_epss_raw is not None else None,
                "previously_vulnerable_advisories": previously_vulnerable_advisories,
                "status": status,
                "has_malware_history": has_malware_history,
                "malware_incident_label": malware_incident_label,
                "historical_advisory_summaries": historical_advisory_summaries,
                "last_advisory_date": last_advisory_date,
                "last_advisory_date_display": format_last_advisory_date(last_advisory_date),
                "severity_chips": derive_advisory_severity_chips(historical_advisory_summaries),
                "advisory_history": derive_advisory_history(
                    historical_advisory_summaries,
                    peak_affected_ids=peak_affected_ids,
                ),
                "linked_incident": linked_incident,
            }
        )

    packages: list[TopPackageRow] = []
    for draft in drafts:
        linked = draft.pop("linked_incident")
        linked_id: str | None = None
        linked_chip: str | None = None
        if linked is not None:
            linked_id = linked.incident_id
            n = len(incident_matched_names[linked.incident_id])
            linked_chip = f"{linked.name} · {n} packages"
        packages.append(
            TopPackageRow(
                **draft,
                linked_incident_id=linked_id,
                linked_incident_chip=linked_chip,
            )
        )

    total = len(packages)
    header = derive_top_packages_header_counts(packages)
    swept_at = _format_swept_at(max((pkg.swept_at for pkg in packages), default=None))
    matched_incident_count = len(incident_matched_names)

    return {
        "packages": packages,
        "total": total,
        "currently_vulnerable_count": header["currently_vulnerable"],
        "clear_count": header["clear"],
        "unknown_count": header["unknown"],
        "malware_last_12mo_count": header["malware_last_12mo"],
        "malware_incident_count": matched_incident_count if matched_incident_count else None,
        "swept_at": swept_at,
        "is_empty": total == 0,
    }


@router.get("/top-packages", response_class=HTMLResponse)
async def top_packages_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "top_packages.html",
        _top_packages_context(),
    )


@router.get("/observatory", response_class=HTMLResponse)
async def observatory_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "observatory.html",
        _observatory_context(),
    )


@router.post("/observatory/refresh", response_class=HTMLResponse)
async def observatory_refresh(request: Request) -> Response:
    return RedirectResponse(url="/observatory", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/scan", response_class=HTMLResponse)
async def scan_page(
    request: Request,
    demo: str | None = None,
    ref: str | None = None,
    url: str | None = None,
    wizard_note: str | None = None,
) -> HTMLResponse:
    prefill_url: str | None = None
    prefill_ref: str | None = ref.strip() if ref and ref.strip() else None
    if demo == "axios":
        prefill_url = "https://github.com/axios/axios"
    elif url and url.strip():
        prefill_url = url.strip()
    return templates.TemplateResponse(
        request,
        "scan.html",
        {"prefill_url": prefill_url, "prefill_ref": prefill_ref, "wizard_note": wizard_note},
    )


@router.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "upload.html")


@router.get("/assessment/{scan_hash}", response_class=HTMLResponse)
async def assessment_page(
    request: Request,
    scan_hash: str,
    wizard_note: str | None = None,
) -> HTMLResponse:
    cached = _load_cached_results(scan_hash)
    recovered = False
    if cached is None:
        inputs = load_scan_inputs(scan_hash, _wizard_db_path())
        if inputs is None:
            return _render_expired_page(request, scan_hash, kind="unknown")
        if inputs.mode in ("A", "C"):
            # Cache-miss recovery triggers a full rescan, so it consumes scan
            # budget; a cache hit above is a cheap read and is never counted.
            denial = check_scan_rate_limit(request)
            if denial is not None:
                return _scan_rate_limited_response(request, denial)
            try:
                cached = await _rescan_from_inputs(inputs)
            except Exception as exc:
                _LOG.warning("permalink rescan failed for %s: %s", scan_hash, exc)
                return _render_expired_page(request, scan_hash, kind="rescan_failed")
            recovered = True
        else:
            return _render_expired_page(request, scan_hash, kind="upload")
    context = build_results_context(cached, scan_hash)
    context["wizard_note"] = wizard_note
    response = templates.TemplateResponse(request, "results.html", context)
    if not recovered:
        set_last_scan_cookie(response, scan_hash)
    return response


@router.get("/observatory/report/{scan_hash}", response_class=HTMLResponse)
async def observatory_frozen_report_page(request: Request, scan_hash: str) -> HTMLResponse:
    try:
        payload = load_observatory_report(scan_hash)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid report hash",
        ) from None
    if payload is None:
        return _render_expired_page(request, scan_hash, kind="frozen_report")
    context = build_results_context(payload, scan_hash)
    return templates.TemplateResponse(request, "results.html", context)


@router.get("/assessment/{scan_hash}/sbom")
async def assessment_sbom_download(request: Request, scan_hash: str) -> Response:
    cached = _load_cached_results(scan_hash)
    if cached is None:
        return templates.TemplateResponse(
            request,
            "results_not_found.html",
            {"scan_hash": scan_hash},
            status_code=status.HTTP_404_NOT_FOUND,
        )

    deps = deps_from_cached(cached)
    if not deps:
        _LOG.error("sbom export: missing deps scan_hash=%s", scan_hash)
        return JSONResponse(
            {"error": "SBOM generation failed: no dependency data"},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    project_name, project_version = project_identity_for_sbom(cached)
    try:
        bom = await run_in_threadpool(
            generate_sbom,
            deps,
            project_name,
            project_version,
        )
    except Exception:
        _LOG.exception("sbom generation failed scan_hash=%s", scan_hash)
        return JSONResponse(
            {"error": "SBOM generation failed"},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    filename = sbom_download_filename(scan_hash, cached)
    body = json.dumps(bom, indent=2) + "\n"
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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
    context = _wizard_plan_context(request, cached, session.scan_hash, session=session)
    return templates.TemplateResponse(request, "plan.html", context)


@router.post("/select", response_class=HTMLResponse)
async def wizard_select_post(
    request: Request,
    selected_candidate_ids: Annotated[list[str], Form()],
    auto_merge_candidate_ids: Annotated[list[str] | None, Form()] = None,
) -> Response:
    guard = get_or_redirect_wizard_session(
        request,
        allowed_steps=(STEP_ASSESSMENT_VIEWED, STEP_SELECTED),
        db_path=_wizard_db_path(),
    )
    if isinstance(guard, RedirectResponse):
        return guard
    session = guard
    merge_ids = auto_merge_candidate_ids or []
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
        validate_auto_merge_subset(selected_candidate_ids, merge_ids)
    except InvalidCandidateSelection as exc:
        context = _wizard_plan_context(
            request,
            cached,
            session.scan_hash,
            selection_error=str(exc),
            session=session,
            submitted_auto_merge_ids=merge_ids,
        )
        return templates.TemplateResponse(
            request,
            "plan.html",
            context,
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    db = _wizard_db_path()
    set_selection(session.token, selected_candidate_ids, merge_ids, db)
    update_step(session.token, STEP_SELECTED, db)
    return RedirectResponse(url="/authorize", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/authorize", response_class=HTMLResponse)
async def wizard_authorize_get(request: Request) -> Response:
    db = _wizard_db_path()
    guard = _load_wizard_session_or_expired(request, db)
    if isinstance(guard, RedirectResponse):
        return guard
    session = guard
    redirect = _authorize_access_redirect(request, session, db)
    if redirect is not None:
        return redirect
    failure_record: ActionRecord | None = None
    if session.current_step == STEP_AUTHORIZE_FAILED:
        failure_record = _linked_action_record(session, db)
        if failure_record is None:
            return expired_wizard_redirect(request)
    cached = _load_cached_results(session.scan_hash)
    if cached is None:
        return templates.TemplateResponse(
            request,
            "results_not_found.html",
            {"scan_hash": session.scan_hash},
            status_code=status.HTTP_404_NOT_FOUND,
        )
    try:
        validate_selection_against_cached(cached, session.selected_candidate_ids)
    except InvalidCandidateSelection:
        return RedirectResponse(
            url=f"/assessment/{session.scan_hash}?wizard_note=stale_selection",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    context = _wizard_authorize_context(
        request,
        cached,
        session.scan_hash,
        session.selected_candidate_ids,
        session.auto_merge_candidate_ids,
    )
    if failure_record is not None:
        context["authorize_failure_reason"] = (
            failure_record.failure_reason or "The remediation action could not be completed."
        )
        context["authorize_retry"] = True
    return templates.TemplateResponse(request, "authorize.html", context)


@router.post("/authorize", response_class=HTMLResponse)
async def wizard_authorize_post(
    request: Request,
) -> Response:
    db = _wizard_db_path()
    guard = _load_wizard_session_or_expired(request, db)
    if isinstance(guard, RedirectResponse):
        return guard
    session = guard
    redirect = _authorize_access_redirect(request, session, db)
    if redirect is not None:
        return redirect
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
    installation_id = _session_installation_id(request)
    if installation_id is None:
        # No verified App install in session — connect first (do not create a null-id run).
        return _redirect_to_github_install()

    denial = check_scan_rate_limit(request)
    if denial is not None:
        return _scan_rate_limited_response(request, denial)

    scan_meta = cached.get("scan_meta") or {}
    url = repo_url_from_scan_meta(scan_meta)
    ref = scan_ref_from_scan_meta(scan_meta)
    try:
        # scan_meta was validated at scan time, but this ref feeds
        # `git clone --branch`; re-check before the run is created.
        validate_git_ref(ref)
    except InvalidGitRefError as exc:
        return _error_card_response(
            request,
            github_fetch_error_card_context(str(exc)),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    db = _wizard_db_path()
    merge_ids = list(session.auto_merge_candidate_ids)
    record = create_action_record(
        scan_hash=session.scan_hash,
        repo_display=str(scan_meta.get("repo_display", "Unknown repository")),
        selected_candidate_ids=ids,
        db_path=db,
        auto_merge_candidate_ids=merge_ids,
    )
    set_action_id(session.token, record.action_id, db)
    scan_id, _queue = await register_scan_stream()
    task = asyncio.create_task(
        run_scan_background(
            scan_id,
            url=url,
            installation_id=installation_id,
            ref=ref,
            assessment_ref=ref,
            selected_candidate_ids=ids,
            action_id=record.action_id,
            db_path=db,
            auto_merge_candidate_ids=frozenset(merge_ids),
        ),
    )
    await attach_background_task(scan_id, task)
    update_step(session.token, STEP_AUTHORIZED, db)
    return RedirectResponse(
        url=f"/process?scan_id={scan_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/process", response_class=HTMLResponse)
async def wizard_process_page(
    request: Request,
    scan_id: str | None = None,
    wizard_note: str | None = None,
) -> Response:
    db = _wizard_db_path()
    guard = _load_wizard_session_or_expired(request, db)
    if isinstance(guard, RedirectResponse):
        return guard
    session = guard
    if session.current_step == STEP_AUTHORIZE_FAILED:
        return RedirectResponse(url="/authorize", status_code=status.HTTP_303_SEE_OTHER)
    if session.current_step not in (STEP_AUTHORIZED, STEP_COMPLETED):
        return expired_wizard_redirect(request)
    cached = _load_cached_results(session.scan_hash)
    if cached is None:
        return templates.TemplateResponse(
            request,
            "results_not_found.html",
            {"scan_hash": session.scan_hash},
            status_code=status.HTTP_404_NOT_FOUND,
        )
    scan_meta = cached.get("scan_meta") or {}
    try:
        github_owner, github_repo = parse_repo_owner_name(scan_meta)
    except ValueError:
        github_owner, github_repo = "", ""
    record = _linked_action_record(session, db)
    action_run = (
        load_action_run_by_wizard_action_id(record.action_id, db) if record is not None else None
    )
    process_hydration = build_process_hydration(record, action_run)
    effective_scan_id = ""
    if (
        scan_id
        and record is not None
        and record.status == "pending"
        and await get_scan_stream_queue(scan_id) is not None
    ):
        effective_scan_id = scan_id
    repo_display = str(scan_meta.get("repo_display", "Unknown repository"))
    return templates.TemplateResponse(
        request,
        "process.html",
        {
            "scan_input_hash": session.scan_hash,
            "scan_id": effective_scan_id,
            "action_id": session.action_id,
            "process_hydration": process_hydration,
            "repo_display": repo_display,
            "ref_display": scan_meta.get("ref", "HEAD"),
            "plan_url": "/select",
            "github_owner": github_owner,
            "github_repo": github_repo,
            **wizard_remediation_failed_card_context(scan_hash=session.scan_hash),
            "wizard_note": wizard_note,
        },
    )


@router.get("/dashboard/wizard-process/{action_id}")
async def wizard_process_hydration(action_id: str) -> JSONResponse:
    """JSON snapshot for hydrating /process after SSE stream expires."""
    db = _wizard_db_path()
    record = load_action_record(action_id, db)
    action_run = load_action_run_by_wizard_action_id(action_id, db) if record is not None else None
    return JSONResponse(build_process_hydration(record, action_run))


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
async def results_redirect_or_action_page(
    request: Request,
    ident: str,
    wizard_note: str | None = None,
) -> Response:
    if _HEX64.match(ident):
        return RedirectResponse(
            url=f"/assessment/{ident}",
            status_code=status.HTTP_301_MOVED_PERMANENTLY,
        )
    if _UUID.match(ident):
        db = _wizard_db_path()
        record = load_action_record(ident, db)
        if record is None:
            return templates.TemplateResponse(
                request,
                "results_not_found.html",
                {"scan_hash": ident},
                status_code=status.HTTP_404_NOT_FOUND,
            )
        from arguss.web.completion_summary import (
            counts_from_pr_outcomes,
            format_completion_breakdown,
        )

        scan_summary = load_scan_summary_for_action_page(record.scan_hash)
        outcome_counts = counts_from_pr_outcomes(record.pr_outcomes)
        completion_breakdown = format_completion_breakdown(outcome_counts)
        action_run = load_action_run_by_wizard_action_id(record.action_id, db)
        failure_reasons: list[str] = []
        if record.status == "failed":
            if record.failure_reason:
                # Persisted run-level reason (newline-joined when several).
                failure_reasons = [
                    line.strip() for line in record.failure_reason.split("\n") if line.strip()
                ]
            else:
                failure_reasons = distinct_failure_reasons(record.pr_outcomes)
        repo_display = record.repo_display
        if action_run is not None:
            cached_mode_c = _load_cached_results(record.scan_hash)
            if cached_mode_c is not None:
                repo_display = str(
                    (cached_mode_c.get("scan_meta") or {}).get("repo_display") or repo_display
                )
        return templates.TemplateResponse(
            request,
            "results_action.html",
            {
                "record": record,
                "scan_summary": scan_summary,
                "completion_breakdown": completion_breakdown,
                "outcome_counts": outcome_counts,
                "short_action_id": record.action_id[:8],
                "wizard_note": wizard_note,
                "action_run": action_run,
                "repo_display": repo_display,
                "failure_reasons": failure_reasons,
            },
        )
    return templates.TemplateResponse(
        request,
        "results_not_found.html",
        {"scan_hash": ident},
        status_code=status.HTTP_404_NOT_FOUND,
    )


@router.post("/dashboard/scan-with-action/start")
async def dashboard_scan_with_action_start(
    request: Request,
    url: Annotated[str, Form()],
    ref: Annotated[str, Form()] = "HEAD",
    selected_candidate_ids: Annotated[list[str] | None, Form()] = None,
) -> Response:
    """Start Mode C from the dashboard; client connects to SSE stream by scan_id."""
    candidate_ids = selected_candidate_ids or None
    try:
        parse_github_url(url)
        validate_git_ref(ref)
    except (InvalidGitHubURLError, InvalidGitRefError) as exc:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": str(exc)},
        )

    installation_id = _session_installation_id(request)
    if installation_id is None:
        return _redirect_to_github_install()

    # This route is JSON (see error_handlers._API_PATH_PREFIXES).
    denial = check_scan_rate_limit(request)
    if denial is not None:
        raise scan_rate_limit_http_exception(denial)

    scan_id, _queue = await register_scan_stream()
    task = asyncio.create_task(
        run_scan_background(
            scan_id,
            url=url,
            installation_id=installation_id,
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
    selected_candidate_ids: Annotated[list[str] | None, Form()] = None,
) -> Response:
    """Blocking Mode C fallback (HTMX). Prefer /start + SSE stream from the UI."""
    candidate_ids = selected_candidate_ids or None
    try:
        parse_github_url(url)
        validate_git_ref(ref)
    except (InvalidGitHubURLError, InvalidGitRefError) as exc:
        return _error_card_response(
            request,
            github_fetch_error_card_context(str(exc)),
        )

    installation_id = _session_installation_id(request)
    if installation_id is None:
        return _redirect_to_github_install()

    denial = check_scan_rate_limit(request)
    if denial is not None:
        return _scan_rate_limited_response(request, denial)

    try:
        result = await execute_scan_with_action(
            url=url,
            installation_id=installation_id,
            ref=ref,
            selected_candidate_ids=candidate_ids,
        )
        return _hx_redirect_response(dict(result.payload), persist_url=url, persist_ref=ref)
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
) -> Response:
    """Mode A from the dashboard. Returns the results fragment."""
    try:
        parsed = parse_github_url(url)
        validate_git_ref(ref)
    except (InvalidGitHubURLError, InvalidGitRefError) as exc:
        return _error_card_response(
            request,
            github_fetch_error_card_context(str(exc)),
        )

    denial = check_scan_rate_limit(request)
    if denial is not None:
        return _scan_rate_limited_response(request, denial)

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

            payload = finalize_scan_payload(
                report,
                lockfile_path,
                scan_meta=build_scan_meta(
                    repo_display=f"{parsed.owner}/{parsed.name}",
                    ref=ref,
                    mode="A",
                    lockfile_path=lockfile_path,
                ),
            )
            return _hx_redirect_response(payload, persist_url=url, persist_ref=ref)
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
    denial = check_scan_rate_limit(request)
    if denial is not None:
        return _scan_rate_limited_response(request, denial)

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

            payload = finalize_scan_payload(
                report,
                lockfile_path,
                scan_meta=build_scan_meta(
                    repo_display="Uploaded lockfile",
                    ref="—",
                    mode="B",
                    lockfile_path=lockfile_path,
                ),
            )
            return _hx_redirect_response(payload)
    except HTTPException as exc:
        return _error_response(request, _http_exception_message(exc))
    except Exception:
        _LOG.exception("unexpected error in dashboard_scan_upload handler")
        return _error_response(request, _INTERNAL_DETAIL)


@router.post("/dashboard/finding-explain", response_class=HTMLResponse)
async def dashboard_finding_explain(
    request: Request,
    scan_hash: Annotated[str, Form()],
    finding_id: Annotated[str, Form()],
    include_version_risks: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Return a cached or freshly generated Claude explanation for one finding."""
    wants_version_risks = _wants_version_risks_section(include_version_risks)
    cache_source = (
        _FINDING_EXPLAIN_SELECT_SOURCE if wants_version_risks else _FINDING_EXPLAIN_SOURCE
    )
    cache_key = _finding_explain_cache_key(scan_hash.strip(), finding_id.strip())
    try:
        cache = _get_explanation_cache()
        cached = cache.get_cached_text(cache_source, cache_key)
        if cached is not None:
            if wants_version_risks:
                sections = _parse_select_explain_cache(cached)
                if sections is not None:
                    return _render_finding_explain_panel(
                        request,
                        explanation=sections.verdict,
                        version_risks=sections.version_risks,
                    )
            else:
                return _render_finding_explain_panel(request, explanation=cached)

        entry = lookup_cached_entry_by_finding_id(scan_hash.strip(), finding_id.strip())
        if entry is None:
            return _render_finding_explain_panel(request, explanation=None)

        if wants_version_risks:
            sections = await run_in_threadpool(explain_finding_verdict_for_select, entry)
            if sections is None:
                return _render_finding_explain_panel(request, explanation=None)

            try:
                cache.set_cached_text(
                    cache_source,
                    cache_key,
                    _select_explain_cache_payload(sections),
                    ttl_seconds=_FINDING_EXPLAIN_TTL_SECONDS,
                )
            except Exception as exc:
                _LOG.warning("finding explain cache write failed: %s", exc)

            return _render_finding_explain_panel(
                request,
                explanation=sections.verdict,
                version_risks=sections.version_risks,
            )

        explanation = await run_in_threadpool(explain_finding_verdict_to_human, entry)
        if explanation is None:
            return _render_finding_explain_panel(request, explanation=None)

        try:
            cache.set_cached_text(
                cache_source,
                cache_key,
                explanation,
                ttl_seconds=_FINDING_EXPLAIN_TTL_SECONDS,
            )
        except Exception as exc:
            _LOG.warning("finding explain cache write failed: %s", exc)

        return _render_finding_explain_panel(request, explanation=explanation)
    except Exception as exc:
        _LOG.warning("finding explain endpoint failed: %s", exc)
        return _render_finding_explain_panel(request, explanation=None)


@router.get("/dashboard/action-run/{action_run_id}", response_class=HTMLResponse)
async def dashboard_action_run_progress(
    request: Request,
    action_run_id: str,
) -> HTMLResponse:
    """HTMX partial: per-candidate merge progress for a Mode C action run."""
    run = load_action_run(action_run_id, _wizard_db_path())
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action run not found")

    repo_display = "Unknown repository"
    cached = _load_cached_results(run.scan_hash)
    if cached is not None:
        repo_display = str((cached.get("scan_meta") or {}).get("repo_display") or repo_display)
    else:
        inputs = load_scan_inputs(run.scan_hash, _wizard_db_path())
        if inputs is not None and inputs.url:
            try:
                parsed = parse_github_url(inputs.url)
                repo_display = f"{parsed.owner}/{parsed.name}"
            except InvalidGitHubURLError:
                repo_display = inputs.url

    return templates.TemplateResponse(
        request,
        "partials/_action_run_progress.html",
        {
            "action_run": run,
            "repo_display": repo_display,
        },
    )


@router.post("/dashboard/chat", response_class=HTMLResponse)
async def dashboard_chat(
    request: Request,
    scan_input_hash: Annotated[str, Form()],
    history_json: Annotated[str, Form()] = "[]",
    question: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Answer a chat question about a previously-run scan."""
    # Each chat turn is an Anthropic call; count it against the scan limits
    # (kill switch respected inside check_scan_rate_limit).
    denial = check_scan_rate_limit(request)
    if denial is not None:
        return templates.TemplateResponse(
            request,
            "partials/_chat_error.html",
            {"message": denial.detail},
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(denial.retry_after_seconds)},
        )

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
