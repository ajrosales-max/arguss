"""Fix discovery: produce FixCandidates from vulnerability findings."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from arguss.core.models import Finding, FixCandidate
from arguss.engine.fix_kind import classify_fix_kind, pick_lowest_version_gt

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FixDiscoveryResult:
    candidates: tuple[FixCandidate, ...]
    skip_reason: str | None = None


def discover_fix_candidates(finding: Finding, repo_id: str) -> FixDiscoveryResult:
    if finding.advisory_id is None:
        logger.warning(
            "skipping fix discovery: finding has no advisory_id (title=%r)",
            finding.title,
        )
        return FixDiscoveryResult((), skip_reason="no_advisory_id")

    if not finding.fixed_versions:
        logger.warning(
            "skipping fix discovery for %s: no fixed version in OSV advisory",
            finding.advisory_id,
        )
        return FixDiscoveryResult((), skip_reason="no_fix_version_in_osv")

    from_version = finding.dependency.version
    to_version = pick_lowest_version_gt(from_version, finding.fixed_versions)
    if to_version is None:
        logger.warning(
            "skipping fix discovery for %s: no fixed version strictly greater than %s "
            "(candidates=%s)",
            finding.advisory_id,
            from_version,
            finding.fixed_versions,
        )
        return FixDiscoveryResult((), skip_reason="no_fix_version_gt_current")

    return FixDiscoveryResult(
        (
            FixCandidate(
                package=finding.dependency.name,
                from_version=from_version,
                to_version=to_version,
                fix_kind=classify_fix_kind(from_version, to_version),
                source_finding_ids=(finding.finding_id,),
                repo_id=repo_id,
            ),
        ),
    )
