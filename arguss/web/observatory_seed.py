"""Load Observatory dashboard data from ``data/observatory-seed.json``."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_SEED_PATH = _REPO_ROOT / "data" / "observatory-seed.json"


@dataclass(frozen=True)
class ObservatoryScan:
    """One row in the Observatory project grid (no letter grade)."""

    name: str
    owner: str
    repo: str
    ref: str
    scanned_at: str | None
    crit_count: int
    high_count: int
    med_count: int
    low_count: int
    total_findings: int
    kev_count: int
    auto_fix_count: int
    review_count: int
    decline_count: int
    scan_hash: str | None = None
    error: str | None = None

    @property
    def github_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}"

    @property
    def has_critical(self) -> bool:
        return self.crit_count > 0

    @property
    def has_kev(self) -> bool:
        return self.kev_count > 0


@dataclass(frozen=True)
class ObservatoryStats:
    projects: int
    total_crit: int
    total_kev: int
    total_auto: int


@dataclass(frozen=True)
class ObservatoryData:
    scans: tuple[ObservatoryScan, ...]
    stats: ObservatoryStats
    last_refreshed: str
    total_projects: int


def default_seed_path() -> Path:
    return _DEFAULT_SEED_PATH


def _int_field(raw: dict[str, Any], key: str) -> int:
    value = raw.get(key)
    if value is None:
        return 0
    return int(value)


def _scan_from_row(raw: dict[str, Any]) -> ObservatoryScan:
    crit = _int_field(raw, "crit_count")
    high = _int_field(raw, "high_count")
    med = _int_field(raw, "med_count")
    low = _int_field(raw, "low_count")
    total = _int_field(raw, "total_findings")
    if total == 0:
        total = crit + high + med + low
    return ObservatoryScan(
        name=str(raw.get("name") or raw.get("repo") or ""),
        owner=str(raw.get("owner") or ""),
        repo=str(raw.get("repo") or ""),
        ref=str(raw.get("ref") or "main"),
        scanned_at=raw.get("scanned_at") if isinstance(raw.get("scanned_at"), str) else None,
        crit_count=crit,
        high_count=high,
        med_count=med,
        low_count=low,
        total_findings=total,
        kev_count=_int_field(raw, "kev_count"),
        auto_fix_count=_int_field(raw, "auto_fix_count"),
        review_count=_int_field(raw, "review_count"),
        decline_count=_int_field(raw, "decline_count"),
        scan_hash=raw.get("scan_hash") if isinstance(raw.get("scan_hash"), str) else None,
        error=raw.get("error") if isinstance(raw.get("error"), str) else None,
    )


def _aggregate_stats(scans: tuple[ObservatoryScan, ...]) -> ObservatoryStats:
    ok = [s for s in scans if s.error is None]
    return ObservatoryStats(
        projects=len(ok),
        total_crit=sum(s.crit_count for s in ok),
        total_kev=sum(s.kev_count for s in ok),
        total_auto=sum(s.auto_fix_count for s in ok),
    )


def _format_last_refreshed(raw: str) -> str:
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return raw
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%b %d, %Y")


def load_observatory_seed(path: Path | None = None) -> ObservatoryData:
    """Read seed JSON and return template-ready Observatory data."""
    seed_path = path or _DEFAULT_SEED_PATH
    document = json.loads(seed_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        msg = f"Observatory seed must be a JSON object: {seed_path}"
        raise ValueError(msg)

    raw_scans = document.get("scans")
    if not isinstance(raw_scans, list):
        msg = f"Observatory seed missing scans array: {seed_path}"
        raise ValueError(msg)

    scans = tuple(_scan_from_row(row) for row in raw_scans if isinstance(row, dict))
    stats = _aggregate_stats(scans)

    last_raw = document.get("last_refreshed") or document.get("generated_at") or ""
    last_refreshed = _format_last_refreshed(str(last_raw)) if last_raw else "unknown"
    total_projects = stats.projects

    return ObservatoryData(
        scans=scans,
        stats=stats,
        last_refreshed=last_refreshed,
        total_projects=total_projects,
    )
