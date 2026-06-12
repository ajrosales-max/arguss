"""Honest completion breakdown for wizard process and action results pages."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from arguss.web.action_records import PROutcome


@dataclass(frozen=True)
class OutcomeCounts:
    opened: int
    already_exists: int
    failed: int
    skipped: int

    @property
    def fail_total(self) -> int:
        return self.failed + self.skipped

    def has_mixed_failure(self) -> bool:
        """True when some PRs succeeded or already existed and some failed/skipped."""
        positive = self.opened + self.already_exists
        return self.fail_total > 0 and positive > 0


def counts_from_scan_complete(event: dict[str, Any]) -> OutcomeCounts:
    return OutcomeCounts(
        opened=int(event.get("succeeded") or 0),
        already_exists=int(event.get("already_exists") or 0),
        failed=int(event.get("failed") or 0),
        skipped=int(event.get("skipped") or 0),
    )


def counts_from_pr_outcomes(outcomes: list[PROutcome]) -> OutcomeCounts:
    opened = sum(1 for o in outcomes if o.status == "opened")
    already_exists = sum(1 for o in outcomes if o.status == "already_exists")
    failed = sum(1 for o in outcomes if o.status == "failed")
    skipped = sum(1 for o in outcomes if o.status == "skipped")
    return OutcomeCounts(
        opened=opened,
        already_exists=already_exists,
        failed=failed,
        skipped=skipped,
    )


def format_completion_breakdown(counts: OutcomeCounts) -> str:
    """Build summary like '18 PRs opened · 3 already open · 2 failed'."""
    if counts.already_exists == 0 and counts.fail_total == 0:
        n = counts.opened
        label = "PR" if n == 1 else "PRs"
        return f"{n} {label} opened"

    parts: list[str] = []
    if counts.opened:
        parts.append(f"{counts.opened} PR{'s' if counts.opened != 1 else ''} opened")
    if counts.already_exists:
        parts.append(f"{counts.already_exists} already open")
    if counts.fail_total:
        parts.append(f"{counts.fail_total} failed")
    return " · ".join(parts)
