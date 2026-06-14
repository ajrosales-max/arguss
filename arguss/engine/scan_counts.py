"""Scan-time counts with balance validation for cached payloads."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Any, Literal

from arguss.core.models import Dependency, Finding, FixTier, NoFixSkip
from arguss.engine.propose import ProposalEntry, ProposalReport

_LOG = logging.getLogger(__name__)


class ScanCountsBalanceError(ValueError):
    """Raised when scan_counts balance invariants fail at finalize time."""


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_PACKAGE_TIER_ORDER = {"auto_merge": 0, "review_required": 1, "decline": 2}


@dataclass(frozen=True)
class ScanBalance:
    ok: bool
    messages: tuple[str, ...]


@dataclass(frozen=True)
class CandidateAggregates:
    max_epss_score: float | None
    max_epss_percentile: float | None
    max_cvss_score: float | None
    severity_min: str | None
    severity_max: str | None
    has_kev: bool


@dataclass(frozen=True)
class CandidateCountRecord:
    candidate_id: str
    package: str
    from_version: str
    to_version: str
    tier: Literal["auto_merge", "review_required", "decline", "unknown"]
    related_finding_ids: tuple[str, ...]
    aggregates: CandidateAggregates


@dataclass(frozen=True)
class PackageNameRollup:
    package: str
    finding_ids: tuple[str, ...]
    finding_count: int
    candidate_ids: tuple[str, ...]
    aggregates: CandidateAggregates


@dataclass(frozen=True)
class ScanCounts:
    total_findings: int
    findings_with_fix: int
    findings_no_fix: int
    findings_by_severity: dict[str, int]
    total_candidates: int
    candidates_auto_merge: int
    candidates_review_required: int
    candidates_decline: int
    candidates_unknown_tier: int
    node_count: int
    clean_node_count: int
    affected_node_count: int
    affected_package_count: int
    package_status_auto_merge: int
    package_status_review_required: int
    package_status_decline: int
    package_status_no_fix: int
    package_status_mixed_no_fix: int
    candidates: tuple[CandidateCountRecord, ...]
    package_rollups: tuple[PackageNameRollup, ...]
    balance: ScanBalance


def _validate_install_keys(deps: list[dict[str, Any]]) -> None:
    """Fail loudly when parser-produced deps carry empty or duplicate install_key.

    Synthetic unit-test deps omit the ``install_key`` field entirely and are skipped.
    Parser-produced payloads always include the field (possibly empty on regression).
    """
    keys_seen: list[str] = []
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        if "install_key" not in dep:
            continue
        key = str(dep.get("install_key") or "").strip()
        if not key:
            package = str(dep.get("package") or "").strip()
            version = str(dep.get("version") or "").strip()
            raise ScanCountsBalanceError(
                f"install_key_empty: parser-produced dep {package}@{version} has empty install_key"
            )
        if key in keys_seen:
            raise ScanCountsBalanceError(f"install_key_duplicate: {key!r}")
        keys_seen.append(key)

    parser_rows = sum(1 for dep in deps if isinstance(dep, dict) and "install_key" in dep)
    if parser_rows and len(keys_seen) != parser_rows:
        raise ScanCountsBalanceError(
            f"install_key_count_mismatch: {len(keys_seen)} unique keys for {parser_rows} parser rows"
        )


def _unique_dep_keys(deps: list[dict[str, Any]]) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    for dep in deps:
        package = str(dep.get("package") or "").strip()
        version = str(dep.get("version") or "").strip()
        if package and version:
            keys.add((package, version))
    return keys


def _severity_band(finding: Finding) -> str:
    if finding.cvss_score is not None:
        from arguss.lenses.vulnerability import _cvss_to_severity

        return _cvss_to_severity(finding.cvss_score)
    return finding.severity


def _aggregates_for_findings(findings: list[Finding]) -> CandidateAggregates:
    if not findings:
        return CandidateAggregates(None, None, None, None, None, False)
    severities = sorted(
        (_severity_band(f) for f in findings), key=lambda s: _SEVERITY_ORDER.get(s, 99)
    )
    max_epss = max((f.epss_score for f in findings if f.epss_score is not None), default=None)
    max_pct = max(
        (f.epss_percentile for f in findings if f.epss_percentile is not None), default=None
    )
    max_cvss = max((f.cvss_score for f in findings if f.cvss_score is not None), default=None)
    return CandidateAggregates(
        max_epss_score=max_epss,
        max_epss_percentile=max_pct,
        max_cvss_score=max_cvss,
        severity_min=severities[0],
        severity_max=severities[-1],
        has_kev=any(f.is_kev for f in findings),
    )


def _normalize_tier(
    entry: ProposalEntry,
) -> Literal["auto_merge", "review_required", "decline", "unknown"]:
    tier = entry.verdict.tier
    if tier is FixTier.AUTO_MERGE:
        return "auto_merge"
    if tier is FixTier.REVIEW_REQUIRED:
        return "review_required"
    if tier is FixTier.DECLINE:
        return "decline"
    return "unknown"


def _finding_from_no_fix(skip: NoFixSkip) -> Finding:
    return Finding(
        dependency=Dependency(
            name=skip.package,
            version=skip.current_version,
            direct=False,
            path=list(skip.dependency_path or []),
        ),
        lens="cve",
        severity=skip.severity or "medium",
        score=0.0,
        title=skip.title,
        description=skip.description,
        advisory_id=skip.advisory_id or None,
        finding_id=skip.finding_id or "",
    )


def build_scan_counts(
    report: ProposalReport,
    deps: list[dict[str, Any]],
    *,
    scan_hash: str | None = None,
) -> ScanCounts:
    _validate_install_keys(deps)
    findings = list(report.findings_snapshot)
    finding_by_id = {f.finding_id: f for f in findings if f.finding_id}
    candidate_records = []
    tier_counts = {"auto_merge": 0, "review_required": 0, "decline": 0, "unknown": 0}
    candidate_finding_map: dict[str, set[str]] = {}
    finding_ids_with_fix: set[str] = set()
    for entry in report.entries:
        tier = _normalize_tier(entry)
        tier_counts[tier] += 1
        related_ids = tuple(sorted({f.finding_id for f in entry.related_findings if f.finding_id}))
        finding_ids_with_fix.update(related_ids)
        candidate_finding_map[entry.candidate.candidate_id] = set(related_ids)
        candidate_records.append(
            CandidateCountRecord(
                candidate_id=entry.candidate.candidate_id,
                package=entry.candidate.package,
                from_version=entry.candidate.from_version,
                to_version=entry.candidate.to_version,
                tier=tier,
                related_finding_ids=related_ids,
                aggregates=_aggregates_for_findings(list(entry.related_findings)),
            )
        )
    total_findings = len(findings)
    findings_with_fix = len(finding_ids_with_fix)
    findings_no_fix = total_findings - findings_with_fix
    findings_by_severity: dict[str, int] = defaultdict(int)
    for finding in findings:
        findings_by_severity[_severity_band(finding)] += 1
    node_keys = _unique_dep_keys(deps)
    node_count = len(node_keys)

    affected_nodes = set()
    affected_packages = set()
    for finding in findings:
        dep = finding.dependency
        affected_nodes.add((dep.name, dep.version))
        affected_packages.add(dep.name)
    affected_in_lockfile = affected_nodes & node_keys
    affected_node_count = len(affected_in_lockfile)
    clean_node_count = max(0, node_count - affected_node_count)
    package_node_tier: dict[tuple[str, str], str] = {}
    for entry in report.entries:
        key = (entry.candidate.package, entry.candidate.from_version)
        tier = _normalize_tier(entry)
        if tier == "unknown":
            continue
        current = package_node_tier.get(key)
        if current is None or _PACKAGE_TIER_ORDER[tier] < _PACKAGE_TIER_ORDER[current]:
            package_node_tier[key] = tier
    no_fix_nodes: set[tuple[str, str]] = set()
    mixed_no_fix_nodes: set[tuple[str, str]] = set()
    for skip in report.skipped_findings:
        if isinstance(skip, NoFixSkip) and skip.package and skip.current_version:
            key = (skip.package, skip.current_version)
            if key not in node_keys:
                continue
            if key in package_node_tier:
                mixed_no_fix_nodes.add(key)
            else:
                no_fix_nodes.add(key)
    package_status_auto_merge = sum(1 for t in package_node_tier.values() if t == "auto_merge")
    package_status_review_required = sum(
        1 for t in package_node_tier.values() if t == "review_required"
    )
    package_status_decline = sum(1 for t in package_node_tier.values() if t == "decline")
    package_status_no_fix = len(no_fix_nodes)
    package_status_mixed_no_fix = len(mixed_no_fix_nodes)
    package_status_sum = (
        package_status_auto_merge
        + package_status_review_required
        + package_status_decline
        + package_status_no_fix
    )

    rollups_by_pkg: dict[str, list[Finding]] = defaultdict(list)
    rollup_candidates: dict[str, set[str]] = defaultdict(set)
    for entry in report.entries:
        pkg = entry.candidate.package
        rollup_candidates[pkg].add(entry.candidate.candidate_id)
        rollups_by_pkg[pkg].extend(entry.related_findings)
    for skip in report.skipped_findings:
        if isinstance(skip, NoFixSkip):
            if skip.finding_id and skip.finding_id in finding_by_id:
                rollups_by_pkg[skip.package].append(finding_by_id[skip.finding_id])
            else:
                rollups_by_pkg[skip.package].append(_finding_from_no_fix(skip))
    package_rollups = []
    for pkg in sorted(rollups_by_pkg.keys(), key=str.lower):
        pkg_findings = rollups_by_pkg[pkg]
        rollup_fids = tuple(sorted({f.finding_id for f in pkg_findings if f.finding_id}))
        package_rollups.append(
            PackageNameRollup(
                package=pkg,
                finding_ids=rollup_fids,
                finding_count=len(rollup_fids),
                candidate_ids=tuple(sorted(rollup_candidates.get(pkg, set()))),
                aggregates=_aggregates_for_findings(pkg_findings),
            )
        )
    no_fix_skip_count = sum(1 for skip in report.skipped_findings if isinstance(skip, NoFixSkip))
    messages = []
    if total_findings != findings_with_fix + findings_no_fix:
        messages.append("finding_partition")
    if findings_no_fix != no_fix_skip_count:
        messages.append("findings_no_fix_skip_count")
    if sum(findings_by_severity.values()) != total_findings:
        messages.append("severity_sum")
    total_candidates = len(candidate_records)
    if total_candidates != sum(tier_counts.values()):
        messages.append("candidate_tier_sum")
    mapped_finding_ids: set[str] = set()
    for cid, related_id_set in candidate_finding_map.items():
        mapped_finding_ids |= related_id_set
        if not related_id_set:
            messages.append(f"candidate_empty_related:{cid}")
    if mapped_finding_ids != finding_ids_with_fix:
        messages.append("finding_candidate_bijection")
    if node_count != clean_node_count + affected_node_count:
        messages.append("node_partition")
    if package_status_sum + clean_node_count != node_count:
        messages.append("package_status_partition")
    if package_status_no_fix + package_status_mixed_no_fix != len(
        no_fix_nodes | mixed_no_fix_nodes
    ):
        messages.append("no_fix_package_partition")
    balance = ScanBalance(ok=not messages, messages=tuple(messages))
    counts = ScanCounts(
        total_findings=total_findings,
        findings_with_fix=findings_with_fix,
        findings_no_fix=findings_no_fix,
        findings_by_severity=dict(findings_by_severity),
        total_candidates=total_candidates,
        candidates_auto_merge=tier_counts["auto_merge"],
        candidates_review_required=tier_counts["review_required"],
        candidates_decline=tier_counts["decline"],
        candidates_unknown_tier=tier_counts["unknown"],
        node_count=node_count,
        clean_node_count=clean_node_count,
        affected_node_count=affected_node_count,
        affected_package_count=len(affected_packages),
        package_status_auto_merge=package_status_auto_merge,
        package_status_review_required=package_status_review_required,
        package_status_decline=package_status_decline,
        package_status_no_fix=package_status_no_fix,
        package_status_mixed_no_fix=package_status_mixed_no_fix,
        candidates=tuple(candidate_records),
        package_rollups=tuple(package_rollups),
        balance=balance,
    )
    if not balance.ok:
        identity = balance.messages[0].split(":", 1)[0]
        _LOG.warning(
            "scan balance failed scan_hash=%s identity=%s messages=%s",
            scan_hash or "pending",
            identity,
            balance.messages,
        )
    return counts


def scan_counts_to_dict(counts: ScanCounts) -> dict[str, Any]:
    return asdict(counts)


def summary_from_scan_counts(counts: ScanCounts, findings: list[Finding]) -> dict[str, Any]:
    """Mirror legacy summary fields from scan_counts (derived at payload assembly).

    Deprecated for internal use — prefer scan_counts in templates and prompts.
    """
    max_epss_score = None
    max_epss_cve_id = None
    max_epss_package = None
    for finding in findings:
        if finding.epss_score is None:
            continue
        if max_epss_score is None or finding.epss_score > max_epss_score:
            max_epss_score = finding.epss_score
            max_epss_cve_id = finding.cve_id
            max_epss_package = finding.dependency.name
    kev_cve_ids = sorted({f.cve_id for f in findings if f.is_kev and f.cve_id})
    kev_count = sum(1 for f in findings if f.is_kev)
    return {
        "total_findings": counts.total_findings,
        "total_candidates": counts.total_candidates,
        "auto_merge_count": counts.candidates_auto_merge,
        "review_required_count": counts.candidates_review_required,
        "decline_count": counts.candidates_decline,
        "max_epss_score": max_epss_score,
        "max_epss_cve_id": max_epss_cve_id,
        "max_epss_package": max_epss_package,
        "kev_count": kev_count,
        "kev_cve_ids": kev_cve_ids,
    }


def log_scan_balance(payload: dict[str, Any], scan_hash: str) -> None:
    raw = payload.get("scan_counts")
    if not isinstance(raw, dict):
        return
    balance = raw.get("balance")
    if not isinstance(balance, dict) or balance.get("ok", True):
        return
    messages = balance.get("messages") or []
    identity = str(messages[0]).split(":", 1)[0] if messages else "unknown"
    _LOG.warning(
        "scan balance failed scan_hash=%s identity=%s messages=%s",
        scan_hash,
        identity,
        messages,
    )
