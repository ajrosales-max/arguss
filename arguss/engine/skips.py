"""Structured skip records for findings with no fix path and lens failures."""

from __future__ import annotations

import re

from arguss.core.models import Finding, LensFailureSkip, NoFixSkip, ScanSkip

_ADVISORY_PREFIX_RE = re.compile(
    r"^(GHSA-[a-z0-9]+(?:-[a-z0-9]+)+|CVE-\d{4}-\d{4,})\s*:\s*",
    re.IGNORECASE,
)

NO_FIX_REASON_LABELS: dict[str, str] = {
    "no_advisory_id": "Fix version not determinable (no advisory ID)",
    "no_fix_version_in_osv": "No fixed version published in OSV",
    "no_fix_version_gt_current": "No OSV fix version newer than the installed version",
    "related_findings_missing": "Could not link consolidated candidate to advisories",
}


def no_fix_reason_label(reason: str) -> str:
    return NO_FIX_REASON_LABELS.get(reason, reason.replace("_", " "))


def _display_title(finding: Finding) -> str:
    advisory_id = finding.advisory_id or finding.title
    raw = finding.title or advisory_id
    title = _ADVISORY_PREFIX_RE.sub("", raw).strip()
    return title or advisory_id


def no_fix_skip_from_finding(finding: Finding, reason: str) -> NoFixSkip:
    path = list(finding.dependency.path) if finding.dependency.path else None
    return NoFixSkip(
        advisory_id=finding.advisory_id or "",
        package=finding.dependency.name,
        current_version=finding.dependency.version,
        title=_display_title(finding),
        description=finding.description,
        cvss_score=finding.cvss_score,
        severity=finding.severity,
        source_url=finding.source_url,
        dependency_path=path,
        epss_score=finding.epss_score,
        epss_percentile=finding.epss_percentile,
        is_kev=finding.is_kev,
        kev_known_ransomware=finding.kev_known_ransomware,
        kev_due_date=finding.kev_due_date,
        reason=reason,
        reason_label=no_fix_reason_label(reason),
    )


def lens_failure_skip_from_scan_skip(skip: ScanSkip) -> LensFailureSkip:
    return LensFailureSkip(
        reason=skip.reason,
        detail=skip.detail,
        lens=skip.lens,
    )
