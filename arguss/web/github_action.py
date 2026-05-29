"""Open GitHub pull requests for in-envelope fix candidates.

This module is the first action-taking layer of Arguss. The fix-confidence
engine decides what to do; this module does it.

Idempotency: every PR is opened on a deterministic branch name
(``arguss/fix-{candidate_id}``). Re-running Mode C on the same repo does not
open duplicate PRs.

Scope: AUTO_MERGE candidates only. The caller filters; this module trusts
that what it receives is in-envelope.
"""

from __future__ import annotations

import base64
import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import httpx

from arguss.core.models import Finding, FixCandidate, FixConfidence, FixTier
from arguss.engine.explanation import explain_verdict_to_human
from arguss.engine.fix_kind import compare_versions, pick_lowest_version_gt
from arguss.engine.propose import ProposalEntry
from arguss.web.lockfile_fix import apply_fix_to_lockfile

_GITHUB_API_BASE = "https://api.github.com"
_HTTP_TIMEOUT_SECONDS = 30.0
_BRANCH_NAME_PREFIX = "arguss/fix-"
_LOCKFILE_PATH = "package-lock.json"

# Footer link for generated PR bodies (Arguss project, not the user's repo).
_ARGUSS_FOOTER_OWNER = "arguss"
_ARGUSS_FOOTER_REPO = "arguss"

_LOG = logging.getLogger(__name__)

_FINE_GRAINED_PAT_PREFIX = re.compile(r"^github_pat_")
_CLASSIC_PAT_PREFIX = re.compile(r"^ghp_")

ActionStatus = Literal["opened", "already_exists", "skipped", "failed"]


@dataclass(frozen=True)
class ActionResult:
    """Outcome of attempting to open a PR for one fix candidate."""

    candidate_id: str
    status: ActionStatus
    pr_url: str | None
    pr_number: int | None
    reason: str | None


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

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def _branch_name(candidate: FixCandidate) -> str:
    return f"{_BRANCH_NAME_PREFIX}{candidate.candidate_id}"


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


def run_mode_c_actions(
    entries: Sequence[ProposalEntry],
    work_tree: Path,
    owner: str,
    name: str,
    pat: str,
) -> list[ActionResult]:
    """Check PAT permissions once, then open PRs for AUTO_MERGE entries."""
    with httpx.Client(
        timeout=_HTTP_TIMEOUT_SECONDS,
        headers=_github_headers(pat),
    ) as client:
        perm = check_pat_permissions(client, pat, owner, name)
        if not perm.sufficient:
            _LOG.warning(
                "PAT insufficient permissions",
                extra={
                    "repo": f"{owner}/{name}",
                    "scopes_found": perm.scopes_found,
                    "required": ["push"],
                },
            )
            raise PatInsufficientError(perm)

        _LOG.info(
            "PAT scope check passed",
            extra={
                "repo": f"{owner}/{name}",
                "scopes_found": perm.scopes_found,
            },
        )

        actions: list[ActionResult] = []
        for entry in entries:
            if entry.verdict.tier is not FixTier.AUTO_MERGE:
                continue
            actions.append(
                open_fix_pr(
                    entry.candidate,
                    entry.verdict,
                    entry.finding,
                    work_tree,
                    owner,
                    name,
                    pat,
                    http_client=client,
                    related_findings=entry.related_findings,
                )
            )
        return actions


def _log_rate_limit_if_needed(response: httpx.Response, *, repo: str, context: str) -> None:
    if response.status_code != 403:
        return
    remaining = response.headers.get("X-RateLimit-Remaining")
    if remaining == "0" or "rate limit" in _github_error_message(response, context).lower():
        _LOG.warning(
            "github rate limit hit",
            extra={"repo": repo, "context": context},
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
        _log_rate_limit_if_needed(response, repo=context, context=context)
        raise GitHubActionError(
            _github_error_message(response, context),
            status_code=response.status_code,
        )
    return response


def _try_explanation(
    candidate: FixCandidate,
    verdict: FixConfidence,
    finding: Finding,
) -> str | None:
    try:
        return explain_verdict_to_human(candidate, verdict, finding)
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


def _render_fixes_section(
    candidate: FixCandidate,
    related_findings: Sequence[Finding],
) -> str:
    if len(related_findings) <= 1:
        finding = related_findings[0]
        advisory_ref = finding.advisory_id or "advisory"
        return f"Fixes [{advisory_ref}]({_finding_osv_url(finding)}): {finding.title}"

    sorted_findings = sorted(
        related_findings,
        key=lambda f: (-(f.cvss_score or 0.0), f.advisory_id or ""),
    )
    count = len(sorted_findings)
    lines = [f"Fixes {count} vulnerabilities in {candidate.package}:", ""]
    for finding in sorted_findings:
        advisory_ref = finding.advisory_id or "advisory"
        cvss = _format_cvss_suffix(finding)
        lines.append(f"- [{advisory_ref}]({_finding_osv_url(finding)}): {finding.title}{cvss}")
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


def _render_pr_body(
    candidate: FixCandidate,
    verdict: FixConfidence,
    finding: Finding,
    *,
    related_findings: Sequence[Finding] | None = None,
    explanation: str | None = None,
) -> str:
    findings = tuple(related_findings) if related_findings else (finding,)
    fixes_block = _render_fixes_section(candidate, findings)
    consolidation = _consolidation_note(candidate, findings)
    reasons_block = "\n".join(f"- ✅ {reason}" for reason in verdict.reasons)
    context_section = ""
    if explanation:
        context_section = f"""

### Context

{explanation}
"""
    return f"""## Arguss auto-fix: {candidate.package} {candidate.from_version} → {candidate.to_version}

{fixes_block}{consolidation}

**Fix-confidence verdict:** AUTO_MERGE (score: {verdict.score}/100)

### What this PR does
Upgrades `{candidate.package}` from `{candidate.from_version}` to `{candidate.to_version}` in `package-lock.json`.
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
) -> str:
    findings = tuple(related_findings) if related_findings else (finding,)
    if len(findings) > 1:
        return (
            f"Arguss: upgrade {candidate.package} "
            f"{candidate.from_version} → {candidate.to_version} "
            f"(resolves {len(findings)} CVEs)"
        )
    advisory_ref = finding.advisory_id or "advisory"
    return f"Arguss: fix {advisory_ref} in {candidate.package}"


def _action_from_pull(candidate_id: str, pull: dict[str, Any]) -> ActionResult:
    return ActionResult(
        candidate_id=candidate_id,
        status="already_exists",
        pr_url=pull.get("html_url") if isinstance(pull.get("html_url"), str) else None,
        pr_number=pull.get("number") if isinstance(pull.get("number"), int) else None,
        reason=None,
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
            return _BranchState(exists=True, pr_result=_action_from_pull(candidate_id, pull))

    return _BranchState(exists=True, pr_result=None)


def _put_lockfile_on_branch(
    client: httpx.Client,
    owner: str,
    name: str,
    branch: str,
    modified: bytes,
    candidate: FixCandidate,
) -> ActionResult | None:
    """Update package-lock.json on a branch. Returns ActionResult on failure."""
    content_url = _api_url(owner, name, f"/contents/{_LOCKFILE_PATH}")
    get_resp = _request(
        client,
        "GET",
        content_url,
        context="fetch lockfile sha",
        params={"ref": branch},
    )
    if get_resp.status_code == 404:
        _LOG.error(
            "lockfile missing on target branch",
            extra={"repo": f"{owner}/{name}", "branch": branch},
        )
        return ActionResult(
            candidate_id=candidate.candidate_id,
            status="failed",
            pr_url=None,
            pr_number=None,
            reason=f"{_LOCKFILE_PATH} not found on branch {branch}",
        )
    if get_resp.status_code != 200:
        return ActionResult(
            candidate_id=candidate.candidate_id,
            status="failed",
            pr_url=None,
            pr_number=None,
            reason=_github_error_message(get_resp, "fetch lockfile sha"),
        )

    contents = _parse_json(get_resp, "lockfile contents")
    current_sha = contents.get("sha")
    if not isinstance(current_sha, str) or not current_sha:
        raise GitHubActionError("GitHub API returned no sha for lockfile contents")

    encoded = base64.b64encode(modified).decode("ascii")
    update_resp = _request(
        client,
        "PUT",
        content_url,
        context="update lockfile",
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
        return ActionResult(
            candidate_id=candidate.candidate_id,
            status="failed",
            pr_url=None,
            pr_number=None,
            reason="lockfile changed on branch before update; manual review required",
        )
    if update_resp.status_code not in (200, 201):
        return ActionResult(
            candidate_id=candidate.candidate_id,
            status="failed",
            pr_url=None,
            pr_number=None,
            reason=_github_error_message(update_resp, "update lockfile"),
        )
    return None


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
    explanation: str | None = None,
) -> ActionResult:
    pr_resp = _request(
        client,
        "POST",
        _api_url(owner, name, "/pulls"),
        context=context,
        json_body={
            "title": _pr_title(candidate, finding, related_findings=related_findings),
            "head": branch,
            "base": default_branch,
            "body": _render_pr_body(
                candidate,
                verdict,
                finding,
                related_findings=related_findings,
                explanation=explanation,
            ),
        },
    )
    if pr_resp.status_code in (200, 201):
        pull = _parse_json(pr_resp, "pull request")
        pr_url = pull.get("html_url")
        pr_number = pull.get("number")
        if not isinstance(pr_url, str) or not isinstance(pr_number, int):
            raise GitHubActionError("GitHub API returned incomplete pull request payload")
        return ActionResult(
            candidate_id=candidate.candidate_id,
            status="opened",
            pr_url=pr_url,
            pr_number=pr_number,
            reason=None,
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
) -> ActionResult:
    """Open a PR for an existing fix branch that has no pull request yet."""
    default_or_failure = _load_default_branch(client, owner, name, candidate.candidate_id)
    if isinstance(default_or_failure, ActionResult):
        return default_or_failure
    default_branch = default_or_failure

    explanation = _try_explanation(candidate, verdict, finding)
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
    related_findings: Sequence[Finding] | None = None,
) -> ActionResult:
    """Open a pull request for a fix candidate.

    See module docstring for workflow and failure semantics.
    """
    branch = _branch_name(candidate)
    lockfile_path = work_tree / _LOCKFILE_PATH

    owns_client = http_client is None
    client = http_client or httpx.Client(
        timeout=_HTTP_TIMEOUT_SECONDS,
        headers=_github_headers(pat),
    )

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
            )

        if not lockfile_path.is_file():
            return ActionResult(
                candidate_id=candidate.candidate_id,
                status="failed",
                pr_url=None,
                pr_number=None,
                reason=f"{_LOCKFILE_PATH} not found in work tree",
            )

        modified = apply_fix_to_lockfile(lockfile_path.read_bytes(), candidate)
        if modified is None:
            return ActionResult(
                candidate_id=candidate.candidate_id,
                status="skipped",
                pr_url=None,
                pr_number=None,
                reason="lockfile layout not supported by v1 modifier",
            )

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

        content_failure = _put_lockfile_on_branch(
            client,
            owner,
            name,
            branch,
            modified,
            candidate,
        )
        if content_failure is not None:
            return content_failure

        explanation = _try_explanation(candidate, verdict, finding)
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
            explanation=explanation,
        )
        return result
    finally:
        if owns_client:
            client.close()
