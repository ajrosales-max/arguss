"""Orchestration: lockfile → findings → candidates → confidence verdicts."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from arguss.core.cache import Cache, get_connection, init_db
from arguss.core.models import (
    Finding,
    FixCandidate,
    FixConfidence,
    FixTier,
    ScanSkip,
    TrustDelta,
)
from arguss.core.parser import parse_lockfile
from arguss.engine.fix_confidence import compute_fix_confidence
from arguss.engine.fix_discovery import discover_fix_candidates
from arguss.lenses._trust_client import TrustClientError
from arguss.lenses.pipeline import fetch_pipeline_snapshot
from arguss.lenses.trust import fetch_delta
from arguss.lenses.vulnerability import VulnerabilityLens
from arguss.settings import settings, validate_settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProposalEntry:
    """One row in the propose-fixes output: finding + candidate + verdict."""

    finding: Finding
    candidate: FixCandidate
    verdict: FixConfidence


@dataclass(frozen=True)
class ProposalSummary:
    """Tier counts and other summary stats."""

    total_findings: int
    total_candidates: int
    auto_merge_count: int
    review_required_count: int
    decline_count: int


@dataclass(frozen=True)
class ProposalReport:
    """The complete output of arguss propose-fixes."""

    repo_path: str
    lockfile_path: str
    entries: tuple[ProposalEntry, ...]
    skipped_findings: tuple[str | ScanSkip, ...]
    summary: ProposalSummary


def _skipped_sort_key(item: str | ScanSkip) -> tuple[int, str]:
    """Deterministic ordering: scan skips first, then finding IDs lexicographically."""
    if isinstance(item, ScanSkip):
        return (0, item.reason)
    return (1, item)


def _fetch_trust_delta_or_none(
    cache: Cache,
    package: str,
    from_version: str,
    to_version: str,
) -> TrustDelta | None:
    """Return TrustDelta or None when registry fetch fails (does not abort the scan)."""
    try:
        return fetch_delta(cache, package, from_version, to_version)
    except TrustClientError as exc:
        logger.warning(
            "trust delta unavailable for %s %s -> %s: %s",
            package,
            from_version,
            to_version,
            exc,
        )
        return None


def _summary_from_entries(
    total_findings: int,
    entries: tuple[ProposalEntry, ...],
) -> ProposalSummary:
    auto_merge = review_required = decline = 0
    for entry in entries:
        tier = entry.verdict.tier
        if tier is FixTier.AUTO_MERGE:
            auto_merge += 1
        elif tier is FixTier.REVIEW_REQUIRED:
            review_required += 1
        elif tier is FixTier.DECLINE:
            decline += 1
    return ProposalSummary(
        total_findings=total_findings,
        total_candidates=len(entries),
        auto_merge_count=auto_merge,
        review_required_count=review_required,
        decline_count=decline,
    )


def propose_fixes(
    lockfile_path: Path,
    repo_path: Path | None = None,
) -> ProposalReport:
    """Build the full proposal report for a lockfile.

    TODO(Week 7+): accept an optional Cache so the agent loop can reuse a connection.

    Args:
        lockfile_path: path to package-lock.json
        repo_path: optional repo root; if None, uses lockfile_path.parent

    Returns:
        ProposalReport with one ProposalEntry per FixCandidate.

    Pipeline:
        1. Parse the lockfile (Week 3 parser)
        2. Run the vulnerability lens to get findings
        3. For each finding, call discover_fix_candidates() → candidates
        4. Fetch one PipelineSnapshot for the repo (Week 5)
        5. For each candidate's package, fetch TrustDelta for the upgrade window
        6. For each candidate, call compute_fix_confidence()
        7. Bundle into ProposalReport

    Raises:
        ParserError: lockfile missing or unsupported
        ZizmorClientError: zizmor binary failure when building pipeline snapshot
    """
    validate_settings()

    lockfile_resolved = lockfile_path.resolve()
    repo_root = lockfile_resolved.parent if repo_path is None else repo_path.resolve()
    repo_id = str(repo_root)

    deps = parse_lockfile(lockfile_resolved)

    conn = get_connection(settings.db_path)
    init_db(conn)
    cache = Cache(conn)

    cve_lens = VulnerabilityLens(cache=cache).scan(deps)
    findings = cve_lens.findings

    pipeline_snapshot = fetch_pipeline_snapshot(repo_root)

    entries: list[ProposalEntry] = []
    skipped: list[str | ScanSkip] = list(cve_lens.scan_skips)

    for finding in findings:
        candidates = discover_fix_candidates(finding, repo_id)
        if not candidates:
            skipped.append(finding.advisory_id or finding.title)
            continue

        for candidate in candidates:
            trust_delta = _fetch_trust_delta_or_none(
                cache,
                candidate.package,
                candidate.from_version,
                candidate.to_version,
            )
            verdict = compute_fix_confidence(
                candidate,
                trust_delta,
                pipeline_snapshot,
            )
            entries.append(ProposalEntry(finding=finding, candidate=candidate, verdict=verdict))

    entries_tuple = tuple(entries)
    return ProposalReport(
        repo_path=repo_id,
        lockfile_path=str(lockfile_resolved),
        entries=entries_tuple,
        skipped_findings=tuple(sorted(skipped, key=_skipped_sort_key)),
        summary=_summary_from_entries(len(findings), entries_tuple),
    )
