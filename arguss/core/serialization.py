"""Shared JSON serialization for ProposalReport and related types."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, cast

from arguss.core.models import SkippedFinding, TrustFlag
from arguss.engine.propose import ProposalEntry, ProposalReport
from arguss.web.github_action import ActionResult


def json_default(obj: object) -> object:
    """Backstop for json.dumps when serializing non-proposal payloads."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, TrustFlag):
        return obj.value
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _to_json_value(obj: Any) -> Any:
    """Recursively convert enums, datetimes, and nested structures to JSON primitives."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {key: _to_json_value(value) for key, value in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_json_value(item) for item in obj]
    return obj


def proposal_entry_payload(entry: ProposalEntry) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        _to_json_value(
            {
                "finding": entry.finding.model_dump(),
                "related_findings": [f.model_dump() for f in entry.related_findings],
                "candidate": asdict(entry.candidate),
                "verdict": asdict(entry.verdict),
            },
        ),
    )


def _skipped_finding_payload(item: SkippedFinding) -> dict[str, object]:
    return item.model_dump()


def proposal_report_payload(report: ProposalReport) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        _to_json_value(
            {
                "repo_path": report.repo_path,
                "lockfile_path": report.lockfile_path,
                "entries": [proposal_entry_payload(e) for e in report.entries],
                "skipped_findings": [
                    _skipped_finding_payload(item) for item in report.skipped_findings
                ],
                "summary": asdict(report.summary),
                "project_scores": (
                    asdict(report.project_scores) if report.project_scores is not None else None
                ),
                "lens_explain": report.lens_explain,
            },
        ),
    )


def proposal_report_with_actions_payload(
    report: ProposalReport,
    actions: Sequence[ActionResult],
) -> dict[str, Any]:
    """Serialize a proposal report plus Mode C action outcomes."""
    payload = proposal_report_payload(report)
    payload["actions"] = cast(
        list[Any],
        _to_json_value([asdict(action) for action in actions]),
    )
    return payload


def attach_executive_summary(payload: dict[str, Any]) -> dict[str, Any]:
    from arguss.engine.scan_counts import log_scan_balance
    from arguss.explanations.executive_summary import generate_executive_summary
    from arguss.explanations.scan_cache import cache_scan_response, scan_input_hash

    payload = dict(payload)
    payload["executive_summary"] = generate_executive_summary(payload)
    scan_hash = cache_scan_response(payload)
    log_scan_balance(payload, scan_hash or scan_input_hash(payload))
    return payload


def finalize_scan_payload(
    report: ProposalReport,
    lockfile_path: Path,
    *,
    scan_meta: dict[str, Any] | None = None,
    actions: Sequence[ActionResult] | None = None,
) -> dict[str, Any]:
    """Build a cache-ready scan payload with scan_counts and derived summary."""
    from pathlib import Path as _Path

    from arguss.engine.scan_counts import (
        build_scan_counts,
        scan_counts_to_dict,
        summary_from_scan_counts,
    )
    from arguss.web.url_scan import attach_scan_deps

    lockfile = _Path(lockfile_path)
    if actions:
        payload = proposal_report_with_actions_payload(report, actions)
    else:
        payload = proposal_report_payload(report)
    attach_scan_deps(payload, lockfile)
    deps = payload.get("deps")
    if not isinstance(deps, list):
        deps = []
    counts = build_scan_counts(report, deps)
    payload["scan_counts"] = scan_counts_to_dict(counts)
    payload["summary"] = summary_from_scan_counts(counts, list(report.findings_snapshot))
    if scan_meta is not None:
        payload["scan_meta"] = scan_meta
    return payload
