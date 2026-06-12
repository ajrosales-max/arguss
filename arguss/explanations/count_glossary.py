"""Canonical scan count units for Claude prompts (exec summary and chat)."""

from __future__ import annotations

from typing import Any

# (scan_counts field key, display label, one-sentence definition)
UNIT_DEFINITIONS: tuple[tuple[str, str, str], ...] = (
    (
        "total_findings",
        "findings",
        "Each finding is one (package node, advisory) pair in the scan.",
    ),
    (
        "total_candidates",
        "upgrade candidates",
        "Each upgrade candidate is one proposed (package name, version line) fix.",
    ),
    (
        "affected_package_count",
        "affected packages",
        "Distinct package names with at least one finding.",
    ),
    (
        "node_count",
        "packages (nodes)",
        "Distinct name@version nodes in the dependency graph.",
    ),
    (
        "clean_node_count",
        "clean packages",
        "Dependency-graph nodes with zero findings.",
    ),
)

_COUNT_KEYS: tuple[str, ...] = (
    "total_findings",
    "total_candidates",
    "affected_package_count",
    "node_count",
    "clean_node_count",
    "affected_node_count",
    "findings_with_fix",
    "findings_no_fix",
    "candidates_auto_merge",
    "candidates_review_required",
    "candidates_decline",
)


def _int_count(scan_counts: dict[str, Any], key: str) -> int:
    raw = scan_counts.get(key)
    if isinstance(raw, bool):
        return int(raw)
    if isinstance(raw, int):
        return raw
    if isinstance(raw, float):
        return int(raw)
    return 0


def build_count_glossary(scan_counts: dict[str, Any]) -> dict[str, Any]:
    """Build labeled counts and definitions for Claude consumption."""
    total_findings = _int_count(scan_counts, "total_findings")
    affected_packages = _int_count(scan_counts, "affected_package_count")
    total_candidates = _int_count(scan_counts, "total_candidates")

    canonical_headline = (
        f"{total_findings} findings across {affected_packages} packages, "
        f"consolidated into {total_candidates} upgrade candidates."
    )

    terms: list[dict[str, Any]] = []
    for field_key, label, definition in UNIT_DEFINITIONS:
        terms.append(
            {
                "label": label,
                "count": _int_count(scan_counts, field_key),
                "definition": definition,
            }
        )

    counts = {key: _int_count(scan_counts, key) for key in _COUNT_KEYS}

    raw_severity = scan_counts.get("findings_by_severity")
    findings_by_severity: dict[str, Any] = (
        dict(raw_severity) if isinstance(raw_severity, dict) else {}
    )

    return {
        "canonical_headline": canonical_headline,
        "terms": terms,
        "counts": counts,
        "findings_by_severity": findings_by_severity,
    }
