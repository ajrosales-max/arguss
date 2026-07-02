"""Open GitHub pull requests for in-envelope fix candidates.

This module is the first action-taking layer of Arguss. The fix-confidence
engine decides what to do; this module does it.

Idempotency: every PR is opened on a deterministic branch name derived from
``(package, from_version, to_version)``. Re-running Mode C on the same repo
does not open duplicate PRs.

Scope: caller supplies selected candidates (including user-overridden tiers).
PR bodies include override warnings for non-AUTO_MERGE tiers.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import httpx

from arguss.core.cache import Cache, get_connection, init_db
from arguss.core.models import Finding, FixCandidate, FixConfidence, FixTier
from arguss.engine.explanation import explain_verdict_to_human
from arguss.engine.fix_kind import compare_versions, pick_lowest_version_gt
from arguss.engine.propose import ProposalEntry
from arguss.lenses._trust_client import TrustRegistryClient
from arguss.settings import settings
from arguss.web.lockfile_fix import (
    LockfileModificationError,
    apply_fix_to_lockfile,
    encode_lockfile,
    encode_package_json,
    parse_lockfile_bytes,
)

_GITHUB_API_BASE = "https://api.github.com"
_HTTP_TIMEOUT_SECONDS = 30.0
_BRANCH_NAME_PREFIX = "arguss/fix-"
_MAX_GIT_REF_LENGTH = 250
_LOCKFILE_PATH = "package-lock.json"
_PACKAGE_JSON_PATH = "package.json"

# Footer link for generated PR bodies (Arguss project, not the user's repo).
_ARGUSS_FOOTER_OWNER = "arguss"
_ARGUSS_FOOTER_REPO = "arguss"

_LOG = logging.getLogger(__name__)

_FINE_GRAINED_PAT_PREFIX = re.compile(r"^github_pat_")
_CLASSIC_PAT_PREFIX = re.compile(r"^ghp_")
_ADVISORY_PREFIX_RE = re.compile(
    r"^(GHSA-[a-z0-9]+(?:-[a-z0-9]+)+|CVE-\d{4}-\d{4,})\s*:\s*",
    re.IGNORECASE,
)

ModeCEventEmitter = Callable[[dict[str, Any]], Awaitable[None]]

ActionStatus = Literal["opened", "already_exists", "skipped", "failed"]


@dataclass(frozen=True)
class ActionResult:
    """Outcome of attempting to open a PR for one fix candidate."""

    candidate_id: str
    status: ActionStatus
    pr_url: str | None
    pr_number: int | None
    reason: str | None
    head_sha: str | None = None


@dataclass(frozen=True)
class PatPermissionResult:
    """Outcome of verifying PAT push access to a repository."""

    sufficient: bool
    scopes_found: list[str]


class PatInsufficientError(Exception):
    """PAT cannot push to the target repository."""

    def __init__(self, result: PatPermissionResult) -> None:
        super().__init__("PAT does not have push permission on the target repository")
        self.result = result


@dataclass(frozen=True)
class _BranchState:
    """Outcome of the idempotency branch / pull lookup."""

    exists: bool
    pr_result: ActionResult | None


class GitHubActionError(Exception):
    """Unexpected GitHub API failure (network, malformed response, auth).

    Expected per-candidate outcomes (branch exists, modifier skip, API 4xx for
    a single operation) are returned via ``ActionResult.status``, not raised.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        rate_limit_exhausted: bool = False,
        rate_limit_reset_epoch: int | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.rate_limit_exhausted = rate_limit_exhausted
        self.rate_limit_reset_epoch = rate_limit_reset_epoch


def _is_valid_git_branch_ref(name: str) -> bool:
    """Return True if name satisfies common git branch ref constraints."""
    if not name or len(name) > _MAX_GIT_REF_LENGTH:
        return False
    if name.startswith("/") or name.endswith("/") or name.endswith(".lock"):
        return False
    if ".." in name or "@{" in name:
        return False
    return not any(ch in name for ch in " \t\n\r\\:~^?*[")


def _derive_branch_name(candidate: FixCandidate) -> str:
    """Generate a CLI-friendly, idempotent branch name from upgrade info.

    Format: arguss/upgrade-<package>-<from>-to-<to>

    Idempotent: same (package, from, to) → same branch name.
    """
    safe_package = candidate.package
    if safe_package.startswith("@"):
        safe_package = safe_package[1:]
    safe_package = safe_package.replace("/", "-")

    branch = f"arguss/upgrade-{safe_package}-{candidate.from_version}-to-{candidate.to_version}"
    if _is_valid_git_branch_ref(branch):
        return branch

    _LOG.warning(
        "derived branch name failed git ref validation; falling back to candidate id",
        extra={
            "package": candidate.package,
            "from_version": candidate.from_version,
            "to_version": candidate.to_version,
            "branch": branch,
        },
    )
    return f"{_BRANCH_NAME_PREFIX}{candidate.candidate_id}"


def _branch_name(candidate: FixCandidate) -> str:
    """Alias for callers/tests; delegates to :func:`_derive_branch_name`."""
    return _derive_branch_name(candidate)


def _build_sibling_index(
    candidates: list[FixCandidate],
) -> dict[str, list[FixCandidate]]:
    """For each package, return all candidates targeting it."""
    by_package: dict[str, list[FixCandidate]] = {}
    for candidate in candidates:
        by_package.setdefault(candidate.package, []).append(candidate)
    return by_package


def _github_headers(pat: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {pat}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _api_url(owner: str, name: str, path: str) -> str:
    return f"{_GITHUB_API_BASE}/repos/{owner}/{name}{path}"


def _parse_json(response: httpx.Response, context: str) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError as exc:
        raise GitHubActionError(f"GitHub API returned malformed JSON for {context}") from exc
    if not isinstance(payload, dict):
        raise GitHubActionError(f"GitHub API returned unexpected JSON for {context}")
    return payload


def _oauth_scopes(response: httpx.Response) -> list[str]:
    raw = response.headers.get("X-OAuth-Scopes", "")
    return [part.strip() for part in raw.split(",") if part.strip()]


def _get_repo_for_pat_check(
    client: httpx.Client,
    owner: str,
    repo: str,
) -> httpx.Response:
    try:
        response = client.get(_api_url(owner, repo, ""))
    except httpx.HTTPError as exc:
        raise GitHubActionError("GitHub API request failed during PAT permission check") from exc
    if response.status_code == 401:
        raise GitHubActionError(
            _github_error_message(response, "PAT permission check"),
            status_code=401,
        )
    return response


def check_pat_permissions(
    client: httpx.Client,
    pat: str,
    owner: str,
    repo: str,
) -> PatPermissionResult:
    """Verify the PAT can push to the target repo (classic or fine-grained)."""
    if _FINE_GRAINED_PAT_PREFIX.match(pat):
        return _check_fine_grained_pat(client, owner, repo)
    if _CLASSIC_PAT_PREFIX.match(pat):
        return _check_classic_pat(client, owner, repo)
    _LOG.warning(
        "unknown PAT format",
        extra={"repo": f"{owner}/{repo}"},
    )
    return PatPermissionResult(sufficient=False, scopes_found=[])


def _check_classic_pat(
    client: httpx.Client,
    owner: str,
    repo: str,
) -> PatPermissionResult:
    response = _get_repo_for_pat_check(client, owner, repo)
    if response.status_code == 404:
        return PatPermissionResult(sufficient=False, scopes_found=[])
    scopes = _oauth_scopes(response)
    sufficient = "repo" in scopes or "public_repo" in scopes
    return PatPermissionResult(sufficient=sufficient, scopes_found=scopes)


def _check_fine_grained_pat(
    client: httpx.Client,
    owner: str,
    repo: str,
) -> PatPermissionResult:
    response = _get_repo_for_pat_check(client, owner, repo)
    if response.status_code == 404:
        return PatPermissionResult(sufficient=False, scopes_found=[])
    if response.status_code != 200:
        return PatPermissionResult(sufficient=False, scopes_found=[])
    payload = _parse_json(response, "repository permissions")
    permissions = payload.get("permissions")
    if not isinstance(permissions, dict):
        return PatPermissionResult(sufficient=False, scopes_found=[])
    granted = [key for key, value in permissions.items() if value]
    sufficient = bool(permissions.get("push"))
    return PatPermissionResult(sufficient=sufficient, scopes_found=granted)


def _check_pat_permissions_sync(pat: str, owner: str, name: str) -> PatPermissionResult:
    """Run PAT scope check with a dedicated sync client (not shared across threads)."""
    with httpx.Client(
        timeout=_HTTP_TIMEOUT_SECONDS,
        headers=_github_headers(pat),
    ) as client:
        return check_pat_permissions(client, pat, owner, name)


_PAT_INSUFFICIENT_REASON = "PAT does not have push permission on the target repository"


async def validate_pat_before_clone(
    owner: str,
    name: str,
    pat: str,
    *,
    event_emitter: ModeCEventEmitter | None = None,
) -> PatPermissionResult:
    """Verify PAT push access before clone. Emits ``pat_validated`` or ``scan_failed``."""
    try:
        perm = await asyncio.to_thread(_check_pat_permissions_sync, pat, owner, name)
    except GitHubActionError as exc:
        _LOG.error(
            "mode C PAT validation failed: %s: %s",
            type(exc).__name__,
            exc,
            extra={"repo": f"{owner}/{name}"},
        )
        _, detail = http_detail_for_github_action_error(exc)
        await _emit_event(event_emitter, {"type": "scan_failed", "reason": detail})
        raise

    if not perm.sufficient:
        _LOG.warning(
            "PAT insufficient permissions",
            extra={
                "repo": f"{owner}/{name}",
                "scopes_found": perm.scopes_found,
                "required": ["push"],
            },
        )
        await _emit_event(
            event_emitter,
            {"type": "scan_failed", "reason": _PAT_INSUFFICIENT_REASON},
        )
        raise PatInsufficientError(perm)

    _LOG.info(
        "PAT scope check passed",
        extra={
            "repo": f"{owner}/{name}",
            "scopes_found": perm.scopes_found,
        },
    )
    await _emit_event(
        event_emitter,
        {"type": "pat_validated", "scopes": perm.scopes_found},
    )
    return perm


async def _emit_event(
    event_emitter: ModeCEventEmitter | None,
    event: dict[str, Any],
) -> None:
    if event_emitter is not None:
        await event_emitter(event)


def _log_pr_outcome(candidate: FixCandidate, result: ActionResult) -> None:
    """Log per-candidate PR outcome (no credentials in fields)."""
    extra: dict[str, Any] = {
        "candidate_id": candidate.candidate_id,
        "package": candidate.package,
        "from_version": candidate.from_version,
        "to_version": candidate.to_version,
    }
    if result.status == "opened":
        _LOG.info(
            "PR opened for %s (%s → %s)",
            candidate.package,
            candidate.from_version,
            candidate.to_version,
            extra={**extra, "pr_number": result.pr_number},
        )
    elif result.status == "already_exists":
        _LOG.info(
            "PR already open for %s (%s → %s)",
            candidate.package,
            candidate.from_version,
            candidate.to_version,
            extra={**extra, "pr_number": result.pr_number},
        )
    elif result.status == "failed":
        _LOG.warning(
            "PR open failed for %s (%s → %s): %s",
            candidate.package,
            candidate.from_version,
            candidate.to_version,
            result.reason,
            extra={**extra, "reason": result.reason},
        )


async def run_mode_c_actions(
    entries: Sequence[ProposalEntry],
    work_tree: Path,
    owner: str,
    name: str,
    pat: str,
    *,
    event_emitter: ModeCEventEmitter | None = None,
) -> list[ActionResult]:
    """Open PRs for the supplied entries concurrently.

    PAT permissions must already be validated by the caller before clone.
    """
    action_entries = list(entries)
    sibling_index = _build_sibling_index([e.candidate for e in action_entries])
    await _emit_event(
        event_emitter,
        {
            "type": "actions_planned",
            "count": len(action_entries),
            "candidates": [
                {
                    "candidate_id": e.candidate.candidate_id,
                    "package": e.candidate.package,
                    "from": e.candidate.from_version,
                    "to": e.candidate.to_version,
                    "fix_kind": e.candidate.fix_kind.value,
                }
                for e in action_entries
            ],
        },
    )
    _LOG.info(
        "mode C PR loop starting",
        extra={"repo": f"{owner}/{name}", "candidate_count": len(action_entries)},
    )

    semaphore = asyncio.Semaphore(settings.mode_c_concurrency)

    async def run_one(entry: ProposalEntry) -> ActionResult:
        candidate = entry.candidate
        async with semaphore:
            await _emit_event(
                event_emitter,
                {
                    "type": "action_started",
                    "candidate_id": candidate.candidate_id,
                    "package": candidate.package,
                    "from": candidate.from_version,
                    "to": candidate.to_version,
                    "fix_kind": candidate.fix_kind.value,
                },
            )
            package_candidates = sibling_index.get(candidate.package, [])
            siblings = [c for c in package_candidates if c.candidate_id != candidate.candidate_id]
            try:
                result = await asyncio.to_thread(
                    open_fix_pr,
                    candidate,
                    entry.verdict,
                    entry.finding,
                    work_tree,
                    owner,
                    name,
                    pat,
                    related_findings=entry.related_findings,
                    siblings=siblings,
                )
            except Exception as exc:
                _LOG.error(
                    "action raised %s: %s",
                    type(exc).__name__,
                    exc,
                    extra={"candidate_id": candidate.candidate_id},
                    exc_info=True,
                )
                result = ActionResult(
                    candidate_id=candidate.candidate_id,
                    status="failed",
                    pr_url=None,
                    pr_number=None,
                    reason=str(exc),
                )

            _log_pr_outcome(candidate, result)

            await _emit_event(
                event_emitter,
                {
                    "type": "action_completed",
                    "candidate_id": result.candidate_id,
                    "status": result.status,
                    "pr_url": result.pr_url,
                    "pr_number": result.pr_number,
                    "reason": result.reason,
                    "package": candidate.package,
                    "from": candidate.from_version,
                    "to": candidate.to_version,
                    "fix_kind": candidate.fix_kind.value,
                },
            )
            return result

    results = list(await asyncio.gather(*(run_one(entry) for entry in action_entries)))
    await _emit_event(
        event_emitter,
        {
            "type": "scan_complete",
            "total": len(results),
            "succeeded": sum(1 for r in results if r.status == "opened"),
            "failed": sum(1 for r in results if r.status == "failed"),
            "skipped": sum(1 for r in results if r.status == "skipped"),
            "already_exists": sum(1 for r in results if r.status == "already_exists"),
        },
    )
    return results


def _rate_limit_reset_epoch(response: httpx.Response) -> int | None:
    raw = response.headers.get("X-RateLimit-Reset")
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _is_rate_limit_exhausted(response: httpx.Response) -> bool:
    return response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0"


def _format_rate_limit_reset(epoch: int | None) -> str:
    if epoch is None:
        return "unknown time"
    return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def rate_limit_user_message(reset_epoch: int | None) -> str:
    return f"GitHub rate limit hit, retry after {_format_rate_limit_reset(reset_epoch)}"


def http_detail_for_github_action_error(exc: GitHubActionError) -> tuple[int, str]:
    """Map a workflow-level GitHubActionError to HTTP status and user-facing detail."""
    from fastapi import status

    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        return status.HTTP_401_UNAUTHORIZED, "Invalid or expired PAT"
    if exc.status_code == status.HTTP_403_FORBIDDEN:
        if exc.rate_limit_exhausted:
            return status.HTTP_403_FORBIDDEN, rate_limit_user_message(exc.rate_limit_reset_epoch)
        return status.HTTP_403_FORBIDDEN, "PAT lacks repo scope on this repository"
    if exc.status_code == status.HTTP_404_NOT_FOUND:
        return status.HTTP_404_NOT_FOUND, "Repository not found or not accessible"
    return (
        status.HTTP_500_INTERNAL_SERVER_ERROR,
        f"Action failed: {type(exc).__name__}",
    )


def _log_rate_limit_if_needed(response: httpx.Response, *, repo: str, context: str) -> None:
    if not _is_rate_limit_exhausted(response):
        return
    reset_epoch = _rate_limit_reset_epoch(response)
    _LOG.warning(
        "github rate limit hit",
        extra={
            "repo": repo,
            "context": context,
            "rate_limit_reset": _format_rate_limit_reset(reset_epoch),
        },
    )


def _github_error_message(response: httpx.Response, context: str) -> str:
    try:
        payload = response.json()
        if isinstance(payload, dict):
            message = payload.get("message")
            if isinstance(message, str) and message:
                return f"{context}: {message}"
    except ValueError:
        pass
    return f"{context}: HTTP {response.status_code}"


def _request(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    context: str,
    json_body: dict[str, Any] | None = None,
    params: dict[str, str] | None = None,
) -> httpx.Response:
    try:
        response = client.request(method, url, json=json_body, params=params)
    except httpx.HTTPError as exc:
        raise GitHubActionError(f"GitHub API request failed during {context}") from exc

    if response.status_code in (401, 403):
        rate_limit_exhausted = _is_rate_limit_exhausted(response)
        _log_rate_limit_if_needed(response, repo=context, context=context)
        raise GitHubActionError(
            _github_error_message(response, context),
            status_code=response.status_code,
            rate_limit_exhausted=rate_limit_exhausted,
            rate_limit_reset_epoch=_rate_limit_reset_epoch(response)
            if rate_limit_exhausted
            else None,
        )
    return response


def _try_explanation(
    candidate: FixCandidate,
    verdict: FixConfidence,
    finding: Finding,
    *,
    related_findings: Sequence[Finding] | None = None,
) -> str | None:
    try:
        return explain_verdict_to_human(
            candidate,
            verdict,
            finding,
            related_findings=related_findings,
        )
    except Exception as exc:
        _LOG.warning(
            "Explanation generation failed for candidate %s: %s",
            candidate.candidate_id,
            exc,
        )
        return None


def _finding_osv_url(finding: Finding) -> str:
    advisory_ref = finding.advisory_id or "advisory"
    return finding.source_url or f"https://osv.dev/vulnerability/{advisory_ref}"


def _format_cvss_suffix(finding: Finding) -> str:
    if finding.cvss_score is not None:
        return f" (CVSS {finding.cvss_score:.1f})"
    return ""


def _render_advisory_line(finding: Finding) -> str:
    """One advisory per line. Single link to OSV; GitHub advisory in details suffix."""
    advisory_id = finding.advisory_id or "advisory"
    osv_url = f"https://osv.dev/vulnerability/{advisory_id}"
    gh_url = f"https://github.com/advisories/{advisory_id}"
    cvss = _format_cvss_suffix(finding)
    raw_title = finding.title or advisory_id
    title = _ADVISORY_PREFIX_RE.sub("", raw_title).strip()
    if not title:
        title = advisory_id
    return f"* **[{advisory_id}]({osv_url})**{cvss}: {title} — [GitHub advisory]({gh_url})"


def _sorted_findings_by_cvss(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    return tuple(
        sorted(
            findings,
            key=lambda f: (-(f.cvss_score or 0.0), f.advisory_id or ""),
        )
    )


def _render_fixes_section(
    candidate: FixCandidate,
    related_findings: Sequence[Finding],
) -> str:
    sorted_findings = _sorted_findings_by_cvss(related_findings)
    if len(sorted_findings) <= 1:
        return f"Fixes\n\n{_render_advisory_line(sorted_findings[0])}"

    count = len(sorted_findings)
    lines = [f"Fixes {count} vulnerabilities in {candidate.package}:", ""]
    for finding in sorted_findings:
        lines.append(_render_advisory_line(finding))
    return "\n".join(lines)


def _render_dependency_paths(findings_in_pr: Sequence[Finding]) -> str:
    """Render lockfile paths showing how this package is pulled in."""
    paths: dict[str, list[str]] = {}
    for finding in findings_in_pr:
        path_str = " → ".join(finding.dependency.path)
        advisory = finding.advisory_id or "advisory"
        paths.setdefault(path_str, []).append(advisory)

    if not paths:
        return ""

    if len(paths) == 1:
        path_str = next(iter(paths))
        return f"**Dependency path:** `{path_str}`"

    lines = ["**Dependency paths:**"]
    multi_finding = len(findings_in_pr) > 1
    for path_str, advisories in list(paths.items())[:5]:
        if multi_finding:
            lines.append(f"- `{path_str}` (via {', '.join(advisories)})")
        else:
            lines.append(f"- `{path_str}`")

    remaining = len(paths) - 5
    if remaining > 0:
        lines.append(f"- _… and {remaining} more transitive paths_")

    return "\n".join(lines)


def _render_sibling_note(
    candidate: FixCandidate,
    siblings: Sequence[FixCandidate],
) -> str:
    """Mention other version lines being patched for the same package."""
    if not siblings:
        return ""

    sibling_versions = sorted(f"v{s.from_version} → v{s.to_version}" for s in siblings)
    lines = [
        f"**Sibling versions:** This lockfile also contains `{candidate.package}` at:",
        "",
    ]
    for sv in sibling_versions:
        lines.append(f"- {sv}")
    lines.extend(
        [
            "",
            "Each version line is patched in a separate PR in this scan. "
            "Merging them independently is intentional — different transitive parents "
            "require different major versions.",
        ]
    )
    return "\n".join(lines)


def _highest_constraint_finding(
    candidate: FixCandidate,
    related_findings: Sequence[Finding],
) -> tuple[Finding, str]:
    """Return the finding whose minimum fix version is highest."""
    best = related_findings[0]
    best_required = (
        pick_lowest_version_gt(candidate.from_version, best.fixed_versions) or candidate.to_version
    )
    for finding in related_findings[1:]:
        required = pick_lowest_version_gt(candidate.from_version, finding.fixed_versions)
        if required is None:
            continue
        if compare_versions(required, best_required) == 1:
            best = finding
            best_required = required
    return best, best_required


def _consolidation_note(
    candidate: FixCandidate,
    related_findings: Sequence[Finding],
) -> str:
    if len(related_findings) <= 1:
        return ""
    constraint_finding, required_version = _highest_constraint_finding(candidate, related_findings)
    advisory_ref = constraint_finding.advisory_id or "advisory"
    kind_label = candidate.fix_kind.value
    return (
        f"\n\nThis is a {kind_label}-level upgrade from "
        f"`{candidate.from_version}` to `{candidate.to_version}` that consolidates "
        f"fixes for {len(related_findings)} advisories. The target version satisfies "
        f"the highest version constraint across all advisories "
        f"({advisory_ref} requires ≥ {required_version})."
    )


def _lockfile_only_remediation_note(
    candidate: FixCandidate,
    files_modified: tuple[str, ...] | None,
) -> str:
    if files_modified != ("package-lock.json",):
        return ""
    return (
        "\n\n**Remediation type:** Lockfile-only update. "
        "`package-lock.json` is updated to pin the patched version of "
        f"`{candidate.package}`; `package.json` is unchanged because the "
        "package is a transitive dependency. npm will install the patched "
        "version on the next `npm install`."
    )


def _format_veto_reason_lines(verdict: FixConfidence) -> str:
    """Format engine veto reasons verbatim for override warnings in PR bodies."""
    signals = verdict.veto_signals
    reasons = verdict.reasons
    lines: list[str] = []
    if signals and reasons:
        for index, reason in enumerate(reasons):
            signal = signals[index] if index < len(signals) else "veto"
            lines.append(f"- `{signal}` — {reason}")
    elif reasons:
        for reason in reasons:
            lines.append(f"- {reason}")
    return "\n".join(lines)


def _render_override_warning(verdict: FixConfidence) -> str:
    """Blockquote override warning prepended to PR bodies for user-overridden tiers."""
    if verdict.tier is FixTier.AUTO_MERGE:
        return ""

    tier_label = verdict.tier.name
    veto_block = _format_veto_reason_lines(verdict)
    quoted_reasons = "\n".join(f"> {line}" for line in veto_block.split("\n") if line)

    if verdict.tier is FixTier.DECLINE:
        assessment = (
            f"> Arguss **DECLINED** this candidate (score: {verdict.score}/100) and did "
            "not recommend opening a PR. The user explicitly chose to proceed anyway."
        )
    else:
        assessment = (
            f"> Arguss assessed this candidate as `{tier_label}` with score "
            f"{verdict.score}/100 and did not recommend auto-merging. The user explicitly "
            "chose to proceed."
        )

    return (
        "> ⚠️ **User-overridden auto-merge envelope**\n"
        ">\n"
        f"{assessment}\n"
        ">\n"
        "> Original veto reasons:\n"
        f"{quoted_reasons}\n"
        ">\n"
        "> Please review the changes carefully before merging.\n\n"
    )


def _render_pr_body(
    candidate: FixCandidate,
    verdict: FixConfidence,
    finding: Finding,
    *,
    related_findings: Sequence[Finding] | None = None,
    siblings: Sequence[FixCandidate] | None = None,
    explanation: str | None = None,
    files_modified: tuple[str, ...] | None = None,
) -> str:
    findings = tuple(related_findings) if related_findings else (finding,)
    fixes_block = _render_fixes_section(candidate, findings)
    consolidation = _consolidation_note(candidate, findings)
    dependency_paths = _render_dependency_paths(findings)
    sibling_note = _render_sibling_note(candidate, siblings or ())
    extra_sections = ""
    if dependency_paths:
        extra_sections += f"\n\n{dependency_paths}"
    if sibling_note:
        extra_sections += f"\n\n{sibling_note}"
    reasons_block = "\n".join(f"- ✅ {reason}" for reason in verdict.reasons)
    context_section = ""
    if explanation:
        context_section = f"""

### Context

{explanation}
"""
    remediation_note = _lockfile_only_remediation_note(candidate, files_modified)
    override_warning = _render_override_warning(verdict)
    tier_label = verdict.tier.name
    return f"""{override_warning}## Arguss auto-fix: {candidate.package} {candidate.from_version} → {candidate.to_version}

{fixes_block}{consolidation}{extra_sections}

**Fix-confidence verdict:** {tier_label} (score: {verdict.score}/100)

### What this PR does
Upgrades `{candidate.package}` from `{candidate.from_version}` to `{candidate.to_version}` in `package-lock.json`.{remediation_note}
{context_section}
### Why the agent is confident
{reasons_block}

### Engine metadata
- Candidate ID: `{candidate.candidate_id}`
- Engine version: `{verdict.engine_version}`
- Evaluated at: `{verdict.evaluated_at.isoformat()}`
- Fix kind: `{candidate.fix_kind.value}`

---
*Generated by [Arguss](https://github.com/{_ARGUSS_FOOTER_OWNER}/{_ARGUSS_FOOTER_REPO}). This PR is open for your review; the agent has NOT merged it. The agent's full reasoning is available in the structured ProposalReport returned by the API call that opened this PR.*
"""


def _pr_title(
    candidate: FixCandidate,
    finding: Finding,
    *,
    related_findings: Sequence[Finding] | None = None,
    siblings: Sequence[FixCandidate] | None = None,
) -> str:
    """Generate PR title with version-line indicator when siblings exist."""
    _ = finding  # primary finding retained for call-site compatibility
    if siblings:
        major = candidate.from_version.split(".")[0]
        version_line = f" v{major} line"
    else:
        version_line = ""

    version_span = f"({candidate.from_version} → {candidate.to_version}"

    if len(candidate.source_finding_ids) == 1:
        advisory = candidate.source_finding_ids[0]
        return f"Arguss: patch {candidate.package}{version_line} {version_span}, fixes {advisory})"

    n = len(candidate.source_finding_ids)
    return f"Arguss: patch {candidate.package}{version_line} {version_span}, resolves {n} CVEs)"


def _fetch_pr_head_sha(
    client: httpx.Client,
    owner: str,
    name: str,
    pr_number: int,
) -> str | None:
    """Return head commit SHA for an open pull request."""
    pull_resp = _request(
        client,
        "GET",
        _api_url(owner, name, f"/pulls/{pr_number}"),
        context="fetch pull head sha",
    )
    if pull_resp.status_code != 200:
        return None
    pull = _parse_json(pull_resp, "pull request")
    head = pull.get("head")
    if not isinstance(head, dict):
        return None
    sha = head.get("sha")
    return sha if isinstance(sha, str) and sha else None


def _action_from_pull(
    client: httpx.Client,
    owner: str,
    name: str,
    candidate_id: str,
    pull: dict[str, Any],
) -> ActionResult:
    pr_number = pull.get("number") if isinstance(pull.get("number"), int) else None
    head_sha: str | None = None
    head = pull.get("head")
    if isinstance(head, dict):
        sha = head.get("sha")
        if isinstance(sha, str) and sha:
            head_sha = sha
    if head_sha is None and pr_number is not None:
        head_sha = _fetch_pr_head_sha(client, owner, name, pr_number)
    return ActionResult(
        candidate_id=candidate_id,
        status="already_exists",
        pr_url=pull.get("html_url") if isinstance(pull.get("html_url"), str) else None,
        pr_number=pr_number,
        reason=None,
        head_sha=head_sha,
    )


def _find_existing_pr(
    client: httpx.Client,
    owner: str,
    name: str,
    branch_name: str,
    candidate_id: str,
) -> _BranchState:
    branch_url = _api_url(owner, name, f"/branches/{branch_name}")
    branch_resp = _request(client, "GET", branch_url, context="check branch")
    if branch_resp.status_code == 404:
        return _BranchState(exists=False, pr_result=None)
    if branch_resp.status_code != 200:
        return _BranchState(
            exists=False,
            pr_result=ActionResult(
                candidate_id=candidate_id,
                status="failed",
                pr_url=None,
                pr_number=None,
                reason=_github_error_message(branch_resp, "check branch"),
            ),
        )

    pulls_url = _api_url(owner, name, "/pulls")
    pulls_resp = _request(
        client,
        "GET",
        pulls_url,
        context="find existing pull request",
        params={"head": f"{owner}:{branch_name}", "state": "all"},
    )
    if pulls_resp.status_code != 200:
        return _BranchState(
            exists=True,
            pr_result=ActionResult(
                candidate_id=candidate_id,
                status="failed",
                pr_url=None,
                pr_number=None,
                reason=_github_error_message(pulls_resp, "find existing pull request"),
            ),
        )

    try:
        pulls = pulls_resp.json()
    except ValueError as exc:
        raise GitHubActionError("GitHub API returned malformed JSON for pull list") from exc

    if not isinstance(pulls, list):
        raise GitHubActionError("GitHub API returned unexpected JSON for pull list")

    head_ref = f"{owner}:{branch_name}"
    for pull in pulls:
        if not isinstance(pull, dict):
            continue
        head = pull.get("head")
        if not isinstance(head, dict):
            continue
        if head.get("ref") == branch_name or head.get("label") == head_ref:
            return _BranchState(
                exists=True,
                pr_result=_action_from_pull(client, owner, name, candidate_id, pull),
            )

    return _BranchState(exists=True, pr_result=None)


def _put_file_on_branch(
    client: httpx.Client,
    owner: str,
    name: str,
    branch: str,
    path: str,
    modified: bytes,
    candidate: FixCandidate,
) -> tuple[ActionResult | None, str | None]:
    """Update one file on a branch via the Contents API.

    Returns ``(failure, commit_sha)`` where ``commit_sha`` comes from the PUT response.
    """
    content_url = _api_url(owner, name, f"/contents/{path}")
    get_resp = _request(
        client,
        "GET",
        content_url,
        context=f"fetch {path} sha",
        params={"ref": branch},
    )
    if get_resp.status_code == 404:
        _LOG.error(
            "file missing on target branch",
            extra={"repo": f"{owner}/{name}", "branch": branch, "path": path},
        )
        return (
            ActionResult(
                candidate_id=candidate.candidate_id,
                status="failed",
                pr_url=None,
                pr_number=None,
                reason=f"{path} not found on branch {branch}",
            ),
            None,
        )
    if get_resp.status_code != 200:
        return (
            ActionResult(
                candidate_id=candidate.candidate_id,
                status="failed",
                pr_url=None,
                pr_number=None,
                reason=_github_error_message(get_resp, f"fetch {path} sha"),
            ),
            None,
        )

    contents = _parse_json(get_resp, f"{path} contents")
    current_sha = contents.get("sha")
    if not isinstance(current_sha, str) or not current_sha:
        raise GitHubActionError(f"GitHub API returned no sha for {path} contents")

    encoded = base64.b64encode(modified).decode("ascii")
    update_resp = _request(
        client,
        "PUT",
        content_url,
        context=f"update {path}",
        json_body={
            "message": (
                f"Arguss: upgrade {candidate.package} "
                f"{candidate.from_version} → {candidate.to_version}"
            ),
            "content": encoded,
            "sha": current_sha,
            "branch": branch,
        },
    )
    if update_resp.status_code == 409:
        return (
            ActionResult(
                candidate_id=candidate.candidate_id,
                status="failed",
                pr_url=None,
                pr_number=None,
                reason=f"{path} changed on branch before update; manual review required",
            ),
            None,
        )
    if update_resp.status_code not in (200, 201):
        return (
            ActionResult(
                candidate_id=candidate.candidate_id,
                status="failed",
                pr_url=None,
                pr_number=None,
                reason=_github_error_message(update_resp, f"update {path}"),
            ),
            None,
        )
    payload = _parse_json(update_resp, f"update {path}")
    commit = payload.get("commit")
    commit_sha: str | None = None
    if isinstance(commit, dict):
        sha = commit.get("sha")
        if isinstance(sha, str) and sha:
            commit_sha = sha
    return None, commit_sha


def _put_files_on_branch(
    client: httpx.Client,
    owner: str,
    name: str,
    branch: str,
    files: Sequence[tuple[str, bytes]],
    candidate: FixCandidate,
) -> tuple[ActionResult | None, str | None]:
    """Update multiple files on a branch. Returns failure or last commit SHA."""
    last_commit_sha: str | None = None
    for path, content in files:
        failure, commit_sha = _put_file_on_branch(
            client,
            owner,
            name,
            branch,
            path,
            content,
            candidate,
        )
        if failure is not None:
            return failure, None
        if commit_sha is not None:
            last_commit_sha = commit_sha
    return None, last_commit_sha


def _put_lockfile_on_branch(
    client: httpx.Client,
    owner: str,
    name: str,
    branch: str,
    modified: bytes,
    candidate: FixCandidate,
) -> tuple[ActionResult | None, str | None]:
    """Update package-lock.json on a branch. Returns failure or commit SHA."""
    return _put_file_on_branch(
        client,
        owner,
        name,
        branch,
        _LOCKFILE_PATH,
        modified,
        candidate,
    )


def _load_default_branch(
    client: httpx.Client,
    owner: str,
    name: str,
    candidate_id: str,
) -> str | ActionResult:
    """Return default branch name, or an ActionResult failure for the caller to return."""
    repo_resp = _request(
        client,
        "GET",
        _api_url(owner, name, ""),
        context="load repository",
    )
    if repo_resp.status_code != 200:
        return ActionResult(
            candidate_id=candidate_id,
            status="failed",
            pr_url=None,
            pr_number=None,
            reason=_github_error_message(repo_resp, "load repository"),
        )
    repo = _parse_json(repo_resp, "repository")
    default_branch = repo.get("default_branch")
    if not isinstance(default_branch, str) or not default_branch:
        raise GitHubActionError("GitHub API returned no default branch")
    return default_branch


def _post_pull_request(
    client: httpx.Client,
    owner: str,
    name: str,
    *,
    candidate: FixCandidate,
    verdict: FixConfidence,
    finding: Finding,
    branch: str,
    default_branch: str,
    context: str,
    related_findings: Sequence[Finding] | None = None,
    siblings: Sequence[FixCandidate] | None = None,
    explanation: str | None = None,
    files_modified: tuple[str, ...] | None = None,
    fresh_head_sha: str | None = None,
) -> ActionResult:
    pr_resp = _request(
        client,
        "POST",
        _api_url(owner, name, "/pulls"),
        context=context,
        json_body={
            "title": _pr_title(
                candidate,
                finding,
                related_findings=related_findings,
                siblings=siblings,
            ),
            "head": branch,
            "base": default_branch,
            "body": _render_pr_body(
                candidate,
                verdict,
                finding,
                related_findings=related_findings,
                siblings=siblings,
                explanation=explanation,
                files_modified=files_modified,
            ),
        },
    )
    if pr_resp.status_code in (200, 201):
        pull = _parse_json(pr_resp, "pull request")
        pr_url = pull.get("html_url")
        pr_number = pull.get("number")
        if not isinstance(pr_url, str) or not isinstance(pr_number, int):
            raise GitHubActionError("GitHub API returned incomplete pull request payload")
        head_sha = fresh_head_sha
        if head_sha is None:
            head_sha = _fetch_pr_head_sha(client, owner, name, pr_number)
        return ActionResult(
            candidate_id=candidate.candidate_id,
            status="opened",
            pr_url=pr_url,
            pr_number=pr_number,
            reason=None,
            head_sha=head_sha,
        )

    if pr_resp.status_code == 422:
        message = _github_error_message(pr_resp, context).lower()
        if "no commits" in message or "no changes" in message:
            return ActionResult(
                candidate_id=candidate.candidate_id,
                status="failed",
                pr_url=None,
                pr_number=None,
                reason=("branch exists with no commits to merge; delete it manually to retry"),
            )

    return ActionResult(
        candidate_id=candidate.candidate_id,
        status="failed",
        pr_url=None,
        pr_number=None,
        reason=_github_error_message(pr_resp, context),
    )


def _resume_open_pr(
    client: httpx.Client,
    owner: str,
    name: str,
    branch: str,
    candidate: FixCandidate,
    verdict: FixConfidence,
    finding: Finding,
    *,
    related_findings: Sequence[Finding] | None = None,
    siblings: Sequence[FixCandidate] | None = None,
) -> ActionResult:
    """Open a PR for an existing fix branch that has no pull request yet."""
    default_or_failure = _load_default_branch(client, owner, name, candidate.candidate_id)
    if isinstance(default_or_failure, ActionResult):
        return default_or_failure
    default_branch = default_or_failure

    explanation = _try_explanation(
        candidate,
        verdict,
        finding,
        related_findings=related_findings,
    )
    result = _post_pull_request(
        client,
        owner,
        name,
        candidate=candidate,
        verdict=verdict,
        finding=finding,
        branch=branch,
        default_branch=default_branch,
        context="resume pull request",
        related_findings=related_findings,
        siblings=siblings,
        explanation=explanation,
    )
    return result


def open_fix_pr(
    candidate: FixCandidate,
    verdict: FixConfidence,
    finding: Finding,
    work_tree: Path,
    owner: str,
    name: str,
    pat: str,
    *,
    http_client: httpx.Client | None = None,
    npm_client: TrustRegistryClient | None = None,
    related_findings: Sequence[Finding] | None = None,
    siblings: Sequence[FixCandidate] | None = None,
) -> ActionResult:
    """Open a pull request for a fix candidate.

    See module docstring for workflow and failure semantics.
    """
    branch = _branch_name(candidate)
    lockfile_path = work_tree / _LOCKFILE_PATH
    package_json_path = work_tree / _PACKAGE_JSON_PATH

    owns_client = http_client is None
    client = http_client or httpx.Client(
        timeout=_HTTP_TIMEOUT_SECONDS,
        headers=_github_headers(pat),
    )
    owns_npm_client = npm_client is None
    npm_registry_client = npm_client
    npm_cache_conn = None
    if npm_registry_client is None:
        npm_cache_conn = get_connection(settings.db_path)
        init_db(npm_cache_conn)
        npm_registry_client = TrustRegistryClient(Cache(npm_cache_conn))

    try:
        branch_state = _find_existing_pr(client, owner, name, branch, candidate.candidate_id)
        if branch_state.pr_result is not None:
            return branch_state.pr_result
        if branch_state.exists:
            return _resume_open_pr(
                client,
                owner,
                name,
                branch,
                candidate,
                verdict,
                finding,
                related_findings=related_findings,
                siblings=siblings,
            )

        if not lockfile_path.is_file():
            return ActionResult(
                candidate_id=candidate.candidate_id,
                status="failed",
                pr_url=None,
                pr_number=None,
                reason=f"{_LOCKFILE_PATH} not found in work tree",
            )
        if not package_json_path.is_file():
            return ActionResult(
                candidate_id=candidate.candidate_id,
                status="failed",
                pr_url=None,
                pr_number=None,
                reason=f"{_PACKAGE_JSON_PATH} not found in work tree",
            )

        try:
            lockfile_bytes = lockfile_path.read_bytes()
            package_json_bytes = package_json_path.read_bytes()
            lockfile_data = parse_lockfile_bytes(lockfile_bytes)
            package_json_data = json.loads(package_json_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return ActionResult(
                candidate_id=candidate.candidate_id,
                status="failed",
                pr_url=None,
                pr_number=None,
                reason=f"could not parse repo manifest files: {exc}",
            )
        if not isinstance(package_json_data, dict):
            return ActionResult(
                candidate_id=candidate.candidate_id,
                status="failed",
                pr_url=None,
                pr_number=None,
                reason="package.json root must be a JSON object",
            )

        try:
            fix_result = apply_fix_to_lockfile(
                lockfile_data,
                package_json_data,
                candidate,
                npm_registry_client,
            )
        except LockfileModificationError as exc:
            return ActionResult(
                candidate_id=candidate.candidate_id,
                status="failed",
                pr_url=None,
                pr_number=None,
                reason=str(exc),
            )

        if not fix_result.applied:
            return ActionResult(
                candidate_id=candidate.candidate_id,
                status="skipped",
                pr_url=None,
                pr_number=None,
                reason=fix_result.skipped_reason,
            )

        files_to_put: list[tuple[str, bytes]] = []
        if _PACKAGE_JSON_PATH in fix_result.files_modified:
            files_to_put.append(
                (_PACKAGE_JSON_PATH, encode_package_json(package_json_data, package_json_bytes)),
            )
        if _LOCKFILE_PATH in fix_result.files_modified:
            files_to_put.append((_LOCKFILE_PATH, encode_lockfile(lockfile_data, lockfile_bytes)))

        default_or_failure = _load_default_branch(client, owner, name, candidate.candidate_id)
        if isinstance(default_or_failure, ActionResult):
            return default_or_failure
        default_branch = default_or_failure

        ref_url = _api_url(owner, name, f"/git/ref/heads/{default_branch}")
        ref_resp = _request(client, "GET", ref_url, context="load default branch ref")
        if ref_resp.status_code != 200:
            return ActionResult(
                candidate_id=candidate.candidate_id,
                status="failed",
                pr_url=None,
                pr_number=None,
                reason=_github_error_message(ref_resp, "load default branch ref"),
            )
        ref_payload = _parse_json(ref_resp, "default branch ref")
        base_sha = ref_payload.get("object", {}).get("sha")
        if not isinstance(base_sha, str):
            raise GitHubActionError("GitHub API returned no commit SHA for default branch")

        create_ref_url = _api_url(owner, name, "/git/refs")
        create_ref_resp = _request(
            client,
            "POST",
            create_ref_url,
            context="create branch",
            json_body={"ref": f"refs/heads/{branch}", "sha": base_sha},
        )
        if create_ref_resp.status_code == 201:
            pass
        elif create_ref_resp.status_code == 422:
            # Branch may have been created concurrently; treat as idempotent path.
            retry_state = _find_existing_pr(
                client,
                owner,
                name,
                branch,
                candidate.candidate_id,
            )
            if retry_state.pr_result is not None:
                return retry_state.pr_result
            if retry_state.exists:
                return _resume_open_pr(
                    client,
                    owner,
                    name,
                    branch,
                    candidate,
                    verdict,
                    finding,
                    related_findings=related_findings,
                    siblings=siblings,
                )
            return ActionResult(
                candidate_id=candidate.candidate_id,
                status="failed",
                pr_url=None,
                pr_number=None,
                reason=_github_error_message(create_ref_resp, "create branch"),
            )
        else:
            return ActionResult(
                candidate_id=candidate.candidate_id,
                status="failed",
                pr_url=None,
                pr_number=None,
                reason=_github_error_message(create_ref_resp, "create branch"),
            )

        content_failure, put_head_sha = _put_files_on_branch(
            client,
            owner,
            name,
            branch,
            files_to_put,
            candidate,
        )
        if content_failure is not None:
            return content_failure

        explanation = _try_explanation(
            candidate,
            verdict,
            finding,
            related_findings=related_findings,
        )
        result = _post_pull_request(
            client,
            owner,
            name,
            candidate=candidate,
            verdict=verdict,
            finding=finding,
            branch=branch,
            default_branch=default_branch,
            context="open pull request",
            related_findings=related_findings,
            siblings=siblings,
            explanation=explanation,
            files_modified=fix_result.files_modified,
            fresh_head_sha=put_head_sha,
        )
        return result
    finally:
        if owns_npm_client and npm_registry_client is not None:
            npm_registry_client.close()
        if npm_cache_conn is not None:
            npm_cache_conn.close()
        if owns_client:
            client.close()
