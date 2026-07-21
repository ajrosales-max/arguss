"""Test helpers for minimal scan_counts on cached scan payloads."""

from __future__ import annotations

from collections import defaultdict
from typing import Any


def _finding_id_from_dict(finding: dict[str, Any], fallback: str) -> str:
    for key in ("finding_id", "advisory_id", "id"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return fallback


def _minimal_aggregates(
    findings: list[dict[str, Any]], entries: list[dict[str, Any]]
) -> dict[str, Any]:
    severities = sorted(
        {str(f.get("severity")) for f in findings if isinstance(f.get("severity"), str)}
    )
    sev_min = severities[0] if severities else None
    sev_max = severities[-1] if severities else None
    epss_scores: list[float] = []
    for entry in entries:
        cand = entry.get("candidate") or {}
        score = cand.get("max_epss_score")
        if isinstance(score, (int, float)):
            epss_scores.append(float(score))
    for finding in findings:
        score = finding.get("epss_score")
        if isinstance(score, (int, float)):
            epss_scores.append(float(score))
    max_epss = max(epss_scores) if epss_scores else None
    cvss_scores: list[float] = []
    for finding in findings:
        score = finding.get("cvss_score")
        if isinstance(score, (int, float)):
            cvss_scores.append(float(score))
    max_cvss = max(cvss_scores) if cvss_scores else None
    has_kev = any(bool(f.get("is_kev")) for f in findings)
    return {
        "max_epss_score": max_epss,
        "max_epss_percentile": None,
        "max_cvss_score": max_cvss,
        "severity_min": sev_min,
        "severity_max": sev_max,
        "has_kev": has_kev,
    }


def _unique_dep_key_count(deps: list[Any]) -> int | None:
    seen: set[tuple[str, str]] = set()
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        package = str(dep.get("package") or "").strip()
        version = str(dep.get("version") or "").strip()
        if package and version:
            seen.add((package, version))
    return len(seen) if seen else None


def attach_minimal_scan_counts(
    payload: dict[str, Any],
    *,
    total_findings: int | None = None,
) -> dict[str, Any]:
    """Ensure payload has scan_counts with package_rollups derived from entries."""
    existing = payload.get("scan_counts")
    base: dict[str, Any] = dict(existing) if isinstance(existing, dict) else {}
    rollups = base.get("package_rollups")
    if isinstance(rollups, (list, tuple)) and len(rollups) > 0:
        sc = dict(base)
        changed = False
        skipped = payload.get("skipped_findings")
        if isinstance(skipped, list):
            skip_n = len(skipped)
            if sc.get("findings_no_fix") != skip_n:
                sc["findings_no_fix"] = skip_n
                changed = True
        if total_findings is not None and sc.get("total_findings") != total_findings:
            sc["total_findings"] = total_findings
            changed = True
        deps_existing = payload.get("deps")
        if isinstance(deps_existing, list):
            node_count = _unique_dep_key_count(deps_existing)
            if node_count is not None:
                if sc.get("node_count") != node_count:
                    sc["node_count"] = node_count
                    changed = True
                by_pkg = len(rollups)
                clean = max(0, node_count - by_pkg)
                affected = min(node_count, by_pkg)
                if sc.get("clean_node_count") != clean:
                    sc["clean_node_count"] = clean
                    changed = True
                if sc.get("affected_node_count") != affected:
                    sc["affected_node_count"] = affected
                    changed = True
        if changed:
            out = dict(payload)
            out["scan_counts"] = sc
            return out
        return payload

    entries = payload.get("entries")
    if not isinstance(entries, list):
        entries = []

    by_pkg_entries: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        candidate = entry.get("candidate") or {}
        package = str(candidate.get("package") or "unknown")
        by_pkg_entries[package].append(entry)

    package_rollups: list[dict[str, Any]] = []
    findings_with_fix = 0
    for package, pkg_entries in by_pkg_entries.items():
        findings: list[dict[str, Any]] = []
        candidate_ids: list[str] = []
        for entry in pkg_entries:
            related = entry.get("related_findings")
            if isinstance(related, list) and related:
                for rf in related:
                    if isinstance(rf, dict):
                        findings.append(rf)
            else:
                finding = entry.get("finding")
                if isinstance(finding, dict):
                    findings.append(finding)
            cand = entry.get("candidate") or {}
            cid = cand.get("candidate_id")
            if isinstance(cid, str) and cid:
                candidate_ids.append(cid)

        finding_count = len(findings) if findings else 1
        findings_with_fix += finding_count
        finding_ids = [
            _finding_id_from_dict(f, f"finding-{package}-{i}")
            for i, f in enumerate(findings if findings else [{}])
        ]
        package_rollups.append(
            {
                "package": package,
                "finding_ids": finding_ids,
                "finding_count": finding_count,
                "candidate_ids": list(candidate_ids),
                "aggregates": _minimal_aggregates(findings, pkg_entries),
            }
        )

    total_candidates = len(entries)
    total_f = total_findings if total_findings is not None else findings_with_fix
    if not total_f and entries:
        total_f = len(entries)

    skipped = payload.get("skipped_findings")
    skip_count = len(skipped) if isinstance(skipped, list) else 0
    if total_findings is None and skip_count:
        total_f = (total_f or 0) + skip_count

    tier_counts = {
        "auto_merge": 0,
        "review_required": 0,
        "decline": 0,
        "unknown": 0,
    }
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        verdict = entry.get("verdict") or {}
        tier = str(verdict.get("tier") or "").strip().lower()
        if tier in ("auto_merge", "review_required", "decline"):
            tier_counts[tier] += 1
        else:
            tier_counts["unknown"] += 1

    deps = payload.get("deps")
    node_count = _unique_dep_key_count(deps if isinstance(deps, list) else [])

    scan_counts: dict[str, Any] = {
        **base,
        "total_findings": base.get("total_findings", total_f),
        "total_candidates": base.get("total_candidates", total_candidates),
        "findings_with_fix": base.get("findings_with_fix", findings_with_fix or total_f),
        "findings_no_fix": skip_count if skip_count else base.get("findings_no_fix", 0),
        "findings_by_severity": base.get("findings_by_severity", {}),
        "candidates_auto_merge": base.get("candidates_auto_merge", tier_counts["auto_merge"]),
        "candidates_review_required": base.get(
            "candidates_review_required", tier_counts["review_required"]
        ),
        "candidates_decline": base.get("candidates_decline", tier_counts["decline"]),
        "candidates_unknown_tier": base.get("candidates_unknown_tier", tier_counts["unknown"]),
        "candidates": base.get("candidates", []),
        "package_rollups": package_rollups,
        "package_status_mixed_no_fix": base.get("package_status_mixed_no_fix", 0),
    }
    if "balance" in base:
        scan_counts["balance"] = base["balance"]

    if node_count is not None:
        scan_counts["node_count"] = node_count
        scan_counts.setdefault("clean_node_count", max(0, node_count - len(by_pkg_entries)))
        scan_counts.setdefault(
            "affected_node_count",
            min(node_count, len(by_pkg_entries)),
        )

    out = dict(payload)
    out["scan_counts"] = scan_counts
    return out
