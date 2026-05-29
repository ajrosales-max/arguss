"""Consolidate per-finding fix candidates into per-package candidates.

When fix discovery emits N candidates for one package (one per CVE), this
module picks the highest viable target version that resolves ALL findings
and emits a single consolidated candidate.

Assumptions:
- Fixes are cumulative within an npm major version line: a fix in version X
  remains fixed in versions > X (until/unless the CVE is re-introduced, which
  OSV's fixed_versions list captures).
- "Highest viable target" = max(per-finding target versions) using semver
  ordering. By construction, this is >= each individual target, so it
  satisfies every finding's constraint.

This module does NOT modify scoring or veto logic. It produces consolidated
FixCandidate objects that the existing fix-confidence engine evaluates
unchanged.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import replace

from arguss.core.models import Finding, FixCandidate
from arguss.engine.fix_kind import classify_fix_kind, compare_versions, pick_lowest_version_gt

logger = logging.getLogger(__name__)


def consolidate_candidates(
    candidates: list[FixCandidate],
    findings: list[Finding],
) -> list[FixCandidate]:
    """Group candidates by package, emit one consolidated candidate per group.

    For each (package, ecosystem) group:
    - 1 candidate: emit as-is, source_finding_ids becomes a singleton tuple
    - N candidates: emit ONE consolidated candidate at max(to_version)
      with all source_finding_ids combined and EPSS/KEV signals aggregated

    Ordering of returned candidates is deterministic (by package name).
    """
    by_package: dict[tuple[str, str, str, str], list[FixCandidate]] = defaultdict(list)
    for candidate in candidates:
        finding = _find_finding(candidate, findings)
        ecosystem = finding.dependency.ecosystem if finding else "npm"
        key = (candidate.package, ecosystem, candidate.from_version, candidate.repo_id)
        by_package[key].append(candidate)

    consolidated: list[FixCandidate] = []
    for (pkg, _ecosystem, _from_v, _repo), pkg_candidates in sorted(by_package.items()):
        if len(pkg_candidates) == 1:
            single = pkg_candidates[0]
            ids = single.source_finding_ids
            consolidated.append(replace(single, source_finding_ids=(ids[0],) if ids else ()))
            continue

        max_target = _max_target(pkg_candidates)
        if max_target is None:
            consolidated.extend(pkg_candidates)
            continue

        related_findings = _findings_for_candidates(pkg_candidates, findings)
        if not _max_target_satisfies_all(
            related_findings, pkg_candidates[0].from_version, max_target
        ):
            logger.warning(
                "consolidated target does not satisfy all findings; "
                "falling back to per-finding candidates",
                extra={
                    "package": pkg,
                    "max_target": max_target,
                    "finding_count": len(related_findings),
                },
            )
            consolidated.extend(pkg_candidates)
            continue

        base = next(c for c in pkg_candidates if c.to_version == max_target)

        consolidated_finding_ids = tuple(
            sorted({fid for c in pkg_candidates for fid in c.source_finding_ids})
        )

        consolidated_max_epss = _max_or_none(c.max_epss_score for c in pkg_candidates)
        consolidated_max_epss_pct = _max_or_none(c.max_epss_percentile for c in pkg_candidates)
        consolidated_has_kev = any(c.has_kev_finding for c in pkg_candidates)

        consolidated_candidate = FixCandidate(
            package=pkg,
            from_version=base.from_version,
            to_version=max_target,
            fix_kind=classify_fix_kind(base.from_version, max_target),
            source_finding_ids=consolidated_finding_ids,
            repo_id=base.repo_id,
            trust_subscore=base.trust_subscore,
            max_epss_score=consolidated_max_epss,
            max_epss_percentile=consolidated_max_epss_pct,
            has_kev_finding=consolidated_has_kev,
        )

        logger.info(
            "consolidated candidates",
            extra={
                "package": pkg,
                "from_version": base.from_version,
                "to_version": max_target,
                "finding_count": len(consolidated_finding_ids),
                "input_candidate_count": len(pkg_candidates),
            },
        )

        consolidated.append(consolidated_candidate)

    return consolidated


def _max_target(candidates: list[FixCandidate]) -> str | None:
    """Return the highest to_version using semver ordering."""
    best: FixCandidate | None = None
    for candidate in candidates:
        if best is None:
            best = candidate
            continue
        cmp = compare_versions(candidate.to_version, best.to_version)
        if cmp is not None and cmp > 0 or cmp is None and candidate.to_version > best.to_version:
            best = candidate
    return best.to_version if best is not None else None


def _max_or_none(values: object) -> float | None:
    filtered = [v for v in values if v is not None]  # type: ignore[union-attr]
    return max(filtered) if filtered else None


def _find_finding(candidate: FixCandidate, findings: list[Finding]) -> Finding | None:
    target_ids = set(candidate.source_finding_ids)
    for finding in findings:
        if finding.advisory_id in target_ids:
            return finding
    return None


def _findings_for_candidates(
    candidates: list[FixCandidate],
    findings: list[Finding],
) -> list[Finding]:
    target_ids = {fid for c in candidates for fid in c.source_finding_ids}
    return [f for f in findings if f.advisory_id in target_ids]


def _max_target_satisfies_all(
    related_findings: list[Finding],
    from_version: str,
    max_target: str,
) -> bool:
    """True when max_target is >= each finding's minimum required fix version."""
    for finding in related_findings:
        if not finding.fixed_versions:
            return False
        required = pick_lowest_version_gt(from_version, finding.fixed_versions)
        if required is None:
            return False
        cmp = compare_versions(max_target, required)
        if cmp is not None and cmp < 0:
            return False
        if cmp is None and max_target < required:
            return False
    return True
