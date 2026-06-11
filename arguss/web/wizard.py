"""Remediation wizard helpers: selection validation, repo URL, PAT prefill."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from fastapi import HTTPException, status

from arguss.core.models import FixTier
from arguss.engine.propose import ProposalEntry
from arguss.settings import settings
from arguss.web.results_context import _entry_candidate_id

_FINE_GRAINED_PAT_BASE = "https://github.com/settings/personal-access-tokens/new"
_CLASSIC_PAT_CREATE_URL = "https://github.com/settings/tokens/new"


class WizardSelectionError(Exception):
    """Base for wizard selection failures surfaced to the user."""


@dataclass(frozen=True)
class InvalidCandidateSelection(WizardSelectionError):
    """Unknown candidate id or tier is not auto_merge (cached or tampered POST)."""

    message: str

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class RescanSelectionChanged(WizardSelectionError):
    """Fresh re-scan no longer has the candidate as AUTO_MERGE — route back to plan."""

    packages: tuple[str, ...]

    @property
    def message(self) -> str:
        if len(self.packages) == 1:
            pkg = self.packages[0]
            return (
                "The re-scan changed this assessment — "
                f"{pkg} is no longer safe to auto-merge. "
                "Review the updated plan and select candidates again."
            )
        listed = ", ".join(self.packages)
        return (
            "The re-scan changed this assessment — these packages are no longer "
            f"safe to auto-merge: {listed}. "
            "Review the updated plan and select candidates again."
        )

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class SelectedCandidateSummary:
    """Display row for authorize / plan carry-forward."""

    candidate_id: str
    package: str
    from_version: str
    to_version: str


def parse_repo_owner_name(scan_meta: dict[str, Any]) -> tuple[str, str]:
    """Split ``scan_meta['repo_display']`` (``owner/name``) into owner and repo name."""
    display = str(scan_meta.get("repo_display") or "").strip()
    if "/" not in display:
        raise ValueError(f"Invalid repo_display (expected owner/name): {display!r}")
    owner, _, name = display.partition("/")
    owner = owner.strip()
    name = name.strip()
    if not owner or not name:
        raise ValueError(f"Invalid repo_display (expected owner/name): {display!r}")
    return owner, name


def repo_url_from_scan_meta(scan_meta: dict[str, Any]) -> str:
    """GitHub.com clone URL for Mode A scans (documented scope: github.com only)."""
    owner, name = parse_repo_owner_name(scan_meta)
    return f"https://github.com/{owner}/{name}"


def scan_ref_from_scan_meta(scan_meta: dict[str, Any]) -> str:
    ref = scan_meta.get("ref")
    if isinstance(ref, str) and ref.strip():
        return ref.strip()
    return "HEAD"


def fine_grained_pat_create_url(
    *,
    repo_display: str | None = None,
) -> str:
    """Pre-filled fine-grained PAT URL (no ``target_name`` or ``workflows`` params)."""
    description = "Opens dependency remediation PRs"
    if repo_display:
        description = f"Opens dependency remediation PRs for {repo_display}"
    query = urlencode(
        {
            "name": "Arguss remediation",
            "description": description,
            "contents": "write",
            "pull_requests": "write",
            "expires_in": "30",
        },
    )
    return f"{_FINE_GRAINED_PAT_BASE}?{query}"


def classic_pat_create_url() -> str:
    return _CLASSIC_PAT_CREATE_URL


def _tier_for_cached_entry(entry: dict[str, Any]) -> str | None:
    verdict = entry.get("verdict") or {}
    tier = verdict.get("tier")
    return str(tier) if isinstance(tier, str) else None


def _package_for_cached_entry(entry: dict[str, Any]) -> str:
    candidate = entry.get("candidate") or {}
    return str(candidate.get("package") or "unknown")


def _is_decline_tier(tier: FixTier | str | None) -> bool:
    if tier is None:
        return False
    if isinstance(tier, FixTier):
        return tier is FixTier.DECLINE
    return str(tier) == FixTier.DECLINE.value


def _assert_decline_override_allowed(tier: FixTier | str | None, package: str) -> None:
    if _is_decline_tier(tier) and not settings.allow_decline_override:
        raise InvalidCandidateSelection(
            f"DECLINE override disabled in this environment. Cannot action {package}.",
        )


def build_cached_entry_index(cached: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Map candidate_id → cached entry dict."""
    index: dict[str, dict[str, Any]] = {}
    for entry in cached.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        cid = _entry_candidate_id(entry)
        index[cid] = entry
    return index


def validate_selection_against_cached(
    cached: dict[str, Any],
    selected_candidate_ids: Sequence[str],
) -> None:
    """Fast feedback on plan → authorize (cached assessment snapshot)."""
    ids = list(selected_candidate_ids)
    if not ids:
        raise InvalidCandidateSelection("Select at least one candidate to continue.")

    index = build_cached_entry_index(cached)
    for cid in ids:
        entry = index.get(cid)
        if entry is None:
            raise InvalidCandidateSelection(
                f"Unknown candidate {cid!r}. Return to the plan step and select again.",
            )
        tier = _tier_for_cached_entry(entry)
        package = _package_for_cached_entry(entry)
        _assert_decline_override_allowed(tier, package)


def validate_selection_against_fresh_report(
    entries: Sequence[ProposalEntry],
    selected_candidate_ids: Sequence[str],
) -> None:
    """Authoritative check after re-scan: every selected id must still exist in the report."""
    ids = list(selected_candidate_ids)
    if not ids:
        raise InvalidCandidateSelection("Select at least one candidate to continue.")

    by_id = {e.candidate.candidate_id: e for e in entries}
    for cid in ids:
        entry = by_id.get(cid)
        if entry is None:
            raise InvalidCandidateSelection(
                f"Unknown candidate {cid!r}. Return to the plan step and select again.",
            )
        _assert_decline_override_allowed(entry.verdict.tier, entry.candidate.package)


def filter_entries_for_action(
    entries: Sequence[ProposalEntry],
    selected_candidate_ids: Sequence[str] | None,
) -> list[ProposalEntry]:
    """Subset of entries to pass to ``run_mode_c_actions`` (upstream filter only).

    When ``selected_candidate_ids`` is None, returns all AUTO_MERGE entries (backward compat).
    Call ``validate_selection_against_fresh_report`` before this when ids are provided.
    """
    if selected_candidate_ids is None:
        return [e for e in entries if e.verdict.tier is FixTier.AUTO_MERGE]

    selected_set = set(selected_candidate_ids)
    filtered = [e for e in entries if e.candidate.candidate_id in selected_set]
    matched = {e.candidate.candidate_id for e in filtered}
    missing = selected_set - matched
    if missing:
        raise InvalidCandidateSelection(
            "Could not match every selected candidate to an entry after re-scan. "
            f"Missing: {', '.join(sorted(missing))}. "
            "Return to the plan step and select again.",
        )
    return filtered


def summarize_selected_candidates(
    cached: dict[str, Any],
    selected_candidate_ids: Sequence[str],
) -> tuple[SelectedCandidateSummary, ...]:
    """Ordered summaries for authorize page (plan POST order preserved)."""
    index = build_cached_entry_index(cached)
    summaries: list[SelectedCandidateSummary] = []
    for cid in selected_candidate_ids:
        entry = index.get(cid)
        if entry is None:
            continue
        candidate = entry.get("candidate") or {}
        summaries.append(
            SelectedCandidateSummary(
                candidate_id=cid,
                package=str(candidate.get("package") or "unknown"),
                from_version=str(candidate.get("from_version") or "?"),
                to_version=str(candidate.get("to_version") or "?"),
            ),
        )
    return tuple(summaries)


def http_exception_for_selection_error(exc: WizardSelectionError) -> HTTPException:
    if isinstance(exc, RescanSelectionChanged):
        status_code = status.HTTP_409_CONFLICT
    else:
        status_code = status.HTTP_400_BAD_REQUEST
    return HTTPException(status_code=status_code, detail=str(exc))


def selection_error_scan_failed_event(exc: WizardSelectionError) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "type": "scan_failed",
        "reason": str(exc),
    }
    if isinstance(exc, RescanSelectionChanged):
        payload["code"] = "selection_stale"
    return payload
