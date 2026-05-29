"""Fix discovery: produce FixCandidates from vulnerability findings.

v1 (Option A): one candidate per finding, target is the lowest OSV ``fixed`` version
strictly greater than the installed version (semver-aware).

Smart target selection (latest patch within minor, alternative upgrade paths) is
deferred to Week 10+ - track in a GitHub issue when filed.
"""

from __future__ import annotations

import logging

from arguss.core.models import Finding, FixCandidate
from arguss.engine.fix_kind import classify_fix_kind, pick_lowest_version_gt

logger = logging.getLogger(__name__)


def discover_fix_candidates(
    finding: Finding,
    repo_id: str,
) -> list[FixCandidate]:
    """Generate FixCandidate(s) for a vulnerability finding.

    v1 behavior: produces exactly zero or one candidate per finding.
    - Returns [] if the finding has no advisory_id
    - Returns [] if the finding has no fixed_versions
    - Returns [one_candidate] using the lowest semver-fixed version > from_version

    Args:
        finding: a Finding from the vulnerability lens (OSV advisory_id and
                 fixed_versions populated for cve findings)
        repo_id: stable identifier for the repository (absolute path or
                 GitHub URL-like string)

    Returns:
        List of FixCandidates. Empty if no fix is available.
    """
    if finding.advisory_id is None:
        logger.warning(
            "skipping fix discovery: finding has no advisory_id (title=%r)",
            finding.title,
        )
        return []

    if not finding.fixed_versions:
        logger.warning(
            "skipping fix discovery for %s: no fixed version in OSV advisory",
            finding.advisory_id,
        )
        return []

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
        return []

    return [
        FixCandidate(
            package=finding.dependency.name,
            from_version=from_version,
            to_version=to_version,
            fix_kind=classify_fix_kind(from_version, to_version),
            source_finding_id=finding.advisory_id,
            repo_id=repo_id,
        )
    ]
