"""Orchestration: lockfile → findings → candidates → confidence verdicts."""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from pathlib import Path

from arguss.core.cache import Cache, get_connection, init_db
from arguss.core.models import (
    Finding,
    FixCandidate,
    FixConfidence,
    FixTier,
    LensScore,
    ProjectScores,
    ScanSkip,
    TrustDelta,
)
from arguss.core.parser import parse_lockfile
from arguss.engine.fix_confidence import compute_fix_confidence
from arguss.engine.fix_discovery import discover_fix_candidates
from arguss.engine.project_scores import build_project_scores
from arguss.lenses._trust_client import TrustClientError
from arguss.lenses.pipeline import fetch_pipeline_snapshot
from arguss.lenses.trust import aggregate_trust_subscores, fetch_delta, fetch_snapshot
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
    max_epss_score: float | None = None
    max_epss_cve_id: str | None = None
    max_epss_package: str | None = None


@dataclass(frozen=True)
class ProposalReport:
    """The complete output of arguss propose-fixes."""

    repo_path: str
    lockfile_path: str
    entries: tuple[ProposalEntry, ...]
    skipped_findings: tuple[str | ScanSkip, ...]
    summary: ProposalSummary
    project_scores: ProjectScores | None = None


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


def _compute_epss_summary(
    findings: list[Finding],
) -> tuple[float | None, str | None, str | None]:
    """Highest EPSS across all findings and its CVE / package."""
    best_score: float | None = None
    best_cve: str | None = None
    best_pkg: str | None = None
    for finding in findings:
        if finding.epss_score is None:
            continue
        if best_score is None or finding.epss_score > best_score:
            best_score = finding.epss_score
            best_cve = finding.cve_id
            best_pkg = finding.dependency.name
    return best_score, best_cve, best_pkg


def _candidate_with_epss(candidate: FixCandidate, finding: Finding) -> FixCandidate:
    """Attach max EPSS fields from the linked finding (one finding per entry)."""
    return replace(
        candidate,
        max_epss_score=finding.epss_score,
        max_epss_percentile=finding.epss_percentile,
    )


def _summary_from_entries(
    total_findings: int,
    entries: tuple[ProposalEntry, ...],
    findings: list[Finding],
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
    max_epss_score, max_epss_cve_id, max_epss_package = _compute_epss_summary(findings)
    return ProposalSummary(
        total_findings=total_findings,
        total_candidates=len(entries),
        auto_merge_count=auto_merge,
        review_required_count=review_required,
        decline_count=decline,
        max_epss_score=max_epss_score,
        max_epss_cve_id=max_epss_cve_id,
        max_epss_package=max_epss_package,
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

    trust_subscore_cache: dict[tuple[str, str], int | None] = {}

    def _trust_subscore_for(package: str, version: str) -> int | None:
        key = (package, version)
        if key not in trust_subscore_cache:
            try:
                snap = fetch_snapshot(cache, package, version)
                trust_subscore_cache[key] = snap.subscore
            except TrustClientError as exc:
                logger.warning(
                    "trust snapshot unavailable for %s@%s: %s",
                    package,
                    version,
                    exc,
                )
                trust_subscore_cache[key] = None
        return trust_subscore_cache[key]

    # Project PRS trust uses direct deps only so scans finish quickly (not every transitive).
    direct_trust_subscores: list[int] = []
    for dep in deps:
        if not dep.direct:
            continue
        sub = _trust_subscore_for(dep.name, dep.version)
        if sub is not None:
            direct_trust_subscores.append(sub)
    trust_lens = LensScore(
        lens="trust",
        score=aggregate_trust_subscores(direct_trust_subscores),
        findings=[],
    )
    pipeline_snapshot = fetch_pipeline_snapshot(repo_root)
    project_scores = build_project_scores(cve_lens, trust_lens, pipeline_snapshot)

    entries: list[ProposalEntry] = []
    skipped: list[str | ScanSkip] = list(cve_lens.scan_skips)

    for finding in findings:
        candidates = discover_fix_candidates(finding, repo_id)
        if not candidates:
            skipped.append(finding.advisory_id or finding.title)
            continue

        for candidate in candidates:
            candidate_with_trust = _candidate_with_epss(
                replace(
                    candidate,
                    trust_subscore=_trust_subscore_for(candidate.package, candidate.from_version),
                ),
                finding,
            )
            trust_delta = _fetch_trust_delta_or_none(
                cache,
                candidate_with_trust.package,
                candidate_with_trust.from_version,
                candidate_with_trust.to_version,
            )
            verdict = compute_fix_confidence(
                candidate_with_trust,
                trust_delta,
                pipeline_snapshot,
            )
            entries.append(
                ProposalEntry(
                    finding=finding,
                    candidate=candidate_with_trust,
                    verdict=verdict,
                )
            )

    entries_tuple = tuple(entries)
    return ProposalReport(
        repo_path=repo_id,
        lockfile_path=str(lockfile_resolved),
        entries=entries_tuple,
        skipped_findings=tuple(sorted(skipped, key=_skipped_sort_key)),
        summary=_summary_from_entries(len(findings), entries_tuple, findings),
        project_scores=project_scores,
    )
