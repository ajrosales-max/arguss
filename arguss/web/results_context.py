"""Build template context for the dedicated /results/{hash} page from cached scan payloads."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

_TRUST_VETO_PRIORITY = (
    "trust.ownership_transferred",
    "trust.new_maintainer",
    "trust.cadence_anomaly",
    "trust.download_collapse",
)
_OWNERSHIP_VETO = "trust.ownership_transferred"


def ordinal(n: int) -> str:
    """1 → '1st', 2 → '2nd', 22 → '22nd', etc."""
    suffix = "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def _current_version(entries: list[dict[str, Any]]) -> str | None:
    for entry in entries:
        finding = entry.get("finding") or {}
        dependency = finding.get("dependency") or {}
        version = dependency.get("version")
        if version:
            return str(version)
        candidate = entry.get("candidate") or {}
        from_version = candidate.get("from_version")
        if from_version:
            return str(from_version)
    return None


@dataclass(frozen=True)
class ResultsPackageView:
    """One grouped package row for the results page."""

    name: str
    current_version: str | None
    entries: list[dict[str, Any]]
    total_count: int
    severity_range: str
    trust_subscore: int | None
    max_epss: float | None
    worst_tier: str
    has_kev: bool
    has_ownership_transferred: bool
    worst_trust_veto: str | None
    transitive_path: str
    summary_tier: str


def _tier_label(tier: str) -> str:
    mapping = {
        "auto_merge": "AUTO-MERGE",
        "review_required": "REVIEW",
        "decline": "DECLINE",
        "mixed": "MIXED",
    }
    return mapping.get(tier, tier.upper().replace("_", "-"))


def _collect_veto_signals(entry: dict[str, Any]) -> list[str]:
    verdict = entry.get("verdict") or {}
    signals = verdict.get("veto_signals") or ()
    return list(signals)


def _worst_trust_veto(entries: list[dict[str, Any]]) -> str | None:
    signals: list[str] = []
    for entry in entries:
        signals.extend(_collect_veto_signals(entry))
    trust_signals = [s for s in signals if isinstance(s, str) and s.startswith("trust.")]
    for preferred in _TRUST_VETO_PRIORITY:
        if preferred in trust_signals:
            return preferred
    return trust_signals[0] if trust_signals else None


def _transitive_path(entries: list[dict[str, Any]]) -> str:
    for entry in entries:
        finding = entry.get("finding") or {}
        dependency = finding.get("dependency") or {}
        path = dependency.get("path") or []
        if path:
            return " → ".join(str(step) for step in path)
    return ""


def _sort_entries_by_epss(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def sort_key(entry: dict[str, Any]) -> tuple[bool, float]:
        candidate = entry.get("candidate") or {}
        epss = candidate.get("max_epss_score")
        return (epss is None, -(epss or 0.0))

    return sorted(entries, key=sort_key)


def build_packages(cached: dict[str, Any]) -> list[ResultsPackageView]:
    """Group cached scan entries into package rows with display metadata."""
    by_pkg: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in cached.get("entries") or []:
        candidate = entry.get("candidate") or {}
        package = candidate.get("package") or "unknown"
        by_pkg[package].append(entry)

    packages: list[ResultsPackageView] = []
    for name, entries in by_pkg.items():
        sorted_entries = _sort_entries_by_epss(entries)
        tiers = {(e.get("verdict") or {}).get("tier") for e in entries}
        tiers.discard(None)
        summary_tier = next(iter(tiers)) if len(tiers) == 1 else "mixed"
        severities = sorted({(e.get("finding") or {}).get("severity") for e in entries})
        severities = [s for s in severities if s]
        severity_range = (
            severities[0] if len(severities) == 1 else f"{severities[0]}–{severities[-1]}"
        )
        trust_sub = (entries[0].get("candidate") or {}).get("trust_subscore")
        epss_scores = [
            (e.get("candidate") or {}).get("max_epss_score")
            for e in entries
            if (e.get("candidate") or {}).get("max_epss_score") is not None
        ]
        max_epss = max(epss_scores) if epss_scores else None
        has_kev = any((e.get("finding") or {}).get("is_kev") for e in entries)
        all_vetoes = [v for e in entries for v in _collect_veto_signals(e)]
        has_ownership = _OWNERSHIP_VETO in all_vetoes
        packages.append(
            ResultsPackageView(
                name=name,
                current_version=_current_version(entries),
                entries=sorted_entries,
                total_count=len(entries),
                severity_range=severity_range or "—",
                trust_subscore=trust_sub,
                max_epss=max_epss,
                worst_tier=_tier_label(summary_tier),
                has_kev=has_kev,
                has_ownership_transferred=has_ownership,
                worst_trust_veto=_worst_trust_veto(entries),
                transitive_path=_transitive_path(entries),
                summary_tier=summary_tier,
            )
        )

    def sort_key(pkg: ResultsPackageView) -> tuple[bool, bool, float, str]:
        return (
            not pkg.has_kev,
            pkg.max_epss is None,
            -(pkg.max_epss or 0.0),
            pkg.name.lower(),
        )

    return sorted(packages, key=sort_key)


def _prs_tier(prs: int | None) -> str:
    if prs is None:
        return "caution"
    if prs >= 70:
        return "safe"
    if prs >= 30:
        return "caution"
    return "danger"


def _format_completed_ago(iso_ts: str | None) -> str:
    if not iso_ts:
        return "just now"
    try:
        completed = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        if completed.tzinfo is None:
            completed = completed.replace(tzinfo=UTC)
        delta = datetime.now(UTC) - completed
        minutes = int(delta.total_seconds() // 60)
        if minutes < 1:
            return "just now"
        if minutes < 60:
            return f"{minutes} min ago"
        hours = minutes // 60
        return f"{hours} hr ago" if hours == 1 else f"{hours} hrs ago"
    except ValueError:
        return "recently"


def build_results_context(cached: dict[str, Any], scan_hash: str) -> dict[str, Any]:
    """Template context for results.html from a cached scan payload."""
    packages = build_packages(cached)
    project_scores = cached.get("project_scores") or {}
    summary = cached.get("summary") or {}
    scan_meta = cached.get("scan_meta") or {}
    prs = project_scores.get("prs")

    scan: dict[str, Any] = {
        **cached,
        "packages": packages,
        "scan_input_hash": scan_hash,
        "dep_counts": scan_meta.get("dep_counts") or {"direct": 0, "transitive": 0},
        "prs_tier": _prs_tier(prs if isinstance(prs, int) else None),
        "completed_ago": _format_completed_ago(scan_meta.get("completed_at")),
        "repo_display": scan_meta.get("repo_display", "Unknown repository"),
        "ref_display": scan_meta.get("ref", "HEAD"),
        "mode_display": scan_meta.get("mode", "—"),
    }

    return {
        "scan": scan,
        "packages": packages,
        "scan_input_hash": scan_hash,
        "project_scores": project_scores,
        "summary": summary,
        "executive_summary": cached.get("executive_summary"),
        "skipped_findings": cached.get("skipped_findings") or [],
        "actions": cached.get("actions"),
    }
