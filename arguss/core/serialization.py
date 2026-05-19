"""Shared JSON serialization for ProposalReport and related types."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict
from datetime import datetime
from enum import Enum
from typing import Any, cast

from arguss.core.models import TrustFlag
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
                "candidate": asdict(entry.candidate),
                "verdict": asdict(entry.verdict),
            },
        ),
    )


def proposal_report_payload(report: ProposalReport) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        _to_json_value(
            {
                "repo_path": report.repo_path,
                "lockfile_path": report.lockfile_path,
                "entries": [proposal_entry_payload(e) for e in report.entries],
                "skipped_findings": list(report.skipped_findings),
                "summary": asdict(report.summary),
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
