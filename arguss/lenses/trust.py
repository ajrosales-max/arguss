"""Trust signal lens — maintainer health, typosquatting, population signals.

Branch 1: ``fetch_snapshot`` builds :class:`~arguss.core.models.TrustSnapshot`.
Branch 2: ``fetch_delta`` builds :class:`~arguss.core.models.TrustDelta`;
:class:`TrustLens` aggregates per-dependency snapshots into a project
:class:`~arguss.core.models.LensScore`.
"""

from __future__ import annotations

import asyncio
import logging
import re
import statistics
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from arguss.core.cache import Cache
from arguss.core.models import (
    Dependency,
    Finding,
    LensScore,
    Severity,
    TrustDelta,
    TrustFlag,
    TrustSnapshot,
)
from arguss.lenses._scorecard_client import fetch_scorecard as fetch_openssf_scorecard
from arguss.lenses._trust_client import TrustClientError, TrustRegistryClient
from arguss.web.github_url import extract_github_owner_repo

_LOG = logging.getLogger(__name__)
_TRUST_LENS_TOP_N = 10


def aggregate_trust_subscores(
    subscores: list[int],
    *,
    top_n: int = _TRUST_LENS_TOP_N,
) -> float:
    """Top-N mean trust score (0–100), matching :meth:`TrustLens.scan` aggregation."""
    if not subscores:
        return 0.0
    ordered = sorted(subscores, reverse=True)
    top = ordered[:top_n] if len(ordered) >= top_n else ordered
    return float(round(sum(top) / len(top), 2))


# Repo root: ``pyproject.toml`` is two levels above this package file.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DATA_DIR = _REPO_ROOT / "data"


@dataclass(frozen=True)
class _TrustSubscoreWeights:
    """v1 default weights for ``TrustSnapshot.subscore`` (0–100 cap, higher = riskier)."""

    sole_maintainer: int = 30
    young_package_days: int = 90
    young_package: int = 20
    typosquat_distance_1: int = 25
    typosquat_distance_2: int = 15
    low_weekly_downloads_threshold: int = 1000
    low_weekly_downloads: int = 10


TRUST_SUBSCORE_WEIGHTS = _TrustSubscoreWeights()


def _load_top_1000_npm() -> frozenset[str]:
    """Load the newest ``data/npm-top-1000-*.txt`` (one name per line). Empty if missing."""
    if not _DATA_DIR.is_dir():
        return frozenset()
    candidates = sorted(_DATA_DIR.glob("npm-top-1000-*.txt"))
    if not candidates:
        return frozenset()
    latest = candidates[-1]
    names: list[str] = []
    for line in latest.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            names.append(s)
    return frozenset(names)


_TOP_1000_NPM: frozenset[str] = _load_top_1000_npm()


def _parse_npm_iso(ts: str) -> datetime:
    """Parse npm ISO timestamps (``...Z`` suffix)."""
    normalized = ts.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _levenshtein(a: str, b: str) -> int:
    """Classic Levenshtein edit distance."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    row = list(range(lb + 1))
    for i in range(1, la + 1):
        cur_row = [i]
        ca = a[i - 1]
        for j in range(1, lb + 1):
            cost = 0 if ca == b[j - 1] else 1
            cur_row.append(
                min(
                    cur_row[j - 1] + 1,
                    row[j] + 1,
                    row[j - 1] + cost,
                )
            )
        row = cur_row
    return row[lb]


def _typosquat_distance(name: str, top_1000: frozenset[str]) -> tuple[int | None, str | None]:
    """Return ``(min_distance, nearest_match)`` against the top-1000 set.

    If ``name`` is in ``top_1000``, returns ``(0, name)``. If ``top_1000`` is
    empty, returns ``(None, None)``. Otherwise scans all entries (bounded 1000).
    """
    if not top_1000:
        return (None, None)
    if name in top_1000:
        return (0, name)
    best_d: int | None = None
    best_name: str | None = None
    for candidate in top_1000:
        d = _levenshtein(name, candidate)
        if best_d is None or d < best_d or (d == best_d and candidate < (best_name or "")):
            best_d = d
            best_name = candidate
    assert best_d is not None and best_name is not None
    return (best_d, best_name)


def _extract_maintainer_logins(
    version_obj: dict[str, Any], packument: dict[str, Any]
) -> tuple[str, ...]:
    """Sorted maintainer login names for a version (fallback to packument root)."""
    raw = version_obj.get("maintainers")
    if raw is None:
        raw = packument.get("maintainers", [])
    logins: set[str] = set()
    if isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, dict):
                n = entry.get("name")
                if isinstance(n, str) and n:
                    logins.add(n)
            elif isinstance(entry, str):
                m = re.match(r"^\s*([^<\s][^<]*)", entry)
                if m:
                    logins.add(m.group(1).strip())
    return tuple(sorted(logins))


def _published_events(packument: dict[str, Any]) -> list[tuple[datetime, str]]:
    """All version publish events from ``packument['time']`` (excludes metadata keys)."""
    times = packument.get("time")
    if not isinstance(times, dict):
        return []
    skip = frozenset({"created", "modified", "unpublished"})
    out: list[tuple[datetime, str]] = []
    for key, val in times.items():
        if key in skip:
            continue
        if not isinstance(val, str):
            continue
        try:
            out.append((_parse_npm_iso(val), key))
        except ValueError:
            continue
    out.sort(key=lambda t: (t[0], t[1]))
    return out


def _first_package_publish(packument: dict[str, Any]) -> datetime | None:
    """Earliest version publish time (package age baseline)."""
    events = _published_events(packument)
    if not events:
        return None
    return events[0][0]


def _published_at_and_gap(
    packument: dict[str, Any], package: str, version: str
) -> tuple[datetime, int | None]:
    """``(published_at, days_since_previous_publish)`` for ``version``."""
    events = _published_events(packument)
    if not events:
        raise TrustClientError(
            f"npm packument for {package!r} has no version publish times in `time`"
        )
    idx = next((i for i, (_, vk) in enumerate(events) if vk == version), None)
    if idx is None:
        raise TrustClientError(
            f"version {version!r} not found in npm `time` map for package {package!r}"
        )
    published_at, _ = events[idx]
    if idx == 0:
        return published_at, None
    prev_dt, _ = events[idx - 1]
    gap = (published_at - prev_dt).days
    return published_at, gap


def _compute_subscore(
    *,
    maintainer_count: int,
    first_publish: datetime | None,
    typosquat_distance: int | None,
    in_top_1000: bool,
    weekly_downloads: int | None,
    weights: _TrustSubscoreWeights,
) -> int:
    """Combine weighted risk signals; cap at 100."""
    score = 0
    now = datetime.now(UTC)
    if maintainer_count == 1:
        score += weights.sole_maintainer
    if first_publish is not None and (now - first_publish).days < weights.young_package_days:
        score += weights.young_package
    if not in_top_1000 and typosquat_distance == 1:
        score += weights.typosquat_distance_1
    elif not in_top_1000 and typosquat_distance == 2:
        score += weights.typosquat_distance_2
    if weekly_downloads is not None and weekly_downloads < weights.low_weekly_downloads_threshold:
        score += weights.low_weekly_downloads
    return min(score, 100)


def fetch_snapshot(
    cache: Cache,
    package: str,
    version: str,
    *,
    include_scorecard: bool = True,
) -> TrustSnapshot:
    """Build a :class:`~arguss.core.models.TrustSnapshot` for ``package@version``.

    Fetches the packument, resolves the version block, computes typosquat
    distance against the bundled top-1000 list, fetches weekly downloads, and
    computes ``subscore``.

    Raises :exc:`TrustClientError` if the package or version is missing from npm.
    """
    with TrustRegistryClient(cache) as client:
        packument = client.fetch_packument(package)
        versions = packument.get("versions")
        if not isinstance(versions, dict) or version not in versions:
            raise TrustClientError(
                f"version {version!r} not found in npm packument for package {package!r}"
            )
        version_obj = versions[version]
        if not isinstance(version_obj, dict):
            raise TrustClientError(f"invalid version object in packument for {package!r}@{version}")

        published_at, days_since_prev = _published_at_and_gap(packument, package, version)

        maintainer_logins = _extract_maintainer_logins(version_obj, packument)
        maintainer_count = len(maintainer_logins)

        ty_dist, ty_near = _typosquat_distance(package, _TOP_1000_NPM)
        in_top = package in _TOP_1000_NPM

        weekly_downloads = client.fetch_weekly_downloads(package)

        first_pub = _first_package_publish(packument)

        sub = _compute_subscore(
            maintainer_count=maintainer_count,
            first_publish=first_pub,
            typosquat_distance=ty_dist,
            in_top_1000=in_top,
            weekly_downloads=weekly_downloads,
            weights=TRUST_SUBSCORE_WEIGHTS,
        )

        scorecard_score: float | None = None
        scorecard_date: str | None = None
        scorecard_top_concerns: tuple[str, ...] | None = None
        if include_scorecard:
            repo_field = version_obj.get("repository")
            if repo_field is None:
                repo_field = packument.get("repository")
            gh = extract_github_owner_repo(repo_field)
            if gh is not None:
                owner, repo_name = gh
                scorecard = asyncio.run(
                    fetch_openssf_scorecard(owner, repo_name, cache=cache),
                )
                if scorecard is not None:
                    scorecard_score = scorecard.score
                    scorecard_date = scorecard.date
                    concerns = scorecard.top_concerns()
                    scorecard_top_concerns = tuple(concerns) if concerns else None

        return TrustSnapshot(
            package=package,
            version=version,
            captured_at=datetime.now(UTC),
            maintainer_count=maintainer_count,
            maintainer_logins=maintainer_logins,
            published_at=published_at,
            days_since_previous_publish=days_since_prev,
            typosquat_distance=ty_dist,
            typosquat_nearest=ty_near,
            weekly_downloads=weekly_downloads,
            scorecard_score=scorecard_score,
            scorecard_date=scorecard_date,
            scorecard_top_concerns=scorecard_top_concerns,
            subscore=sub,
        )


def _weekly_downloads_change_pct(from_snap: TrustSnapshot, to_snap: TrustSnapshot) -> float | None:
    """Relative change ``(to - from) / from``; ``None`` if undefined."""
    fd = from_snap.weekly_downloads
    td = to_snap.weekly_downloads
    if fd is None or td is None:
        return None
    if fd == 0 and td > 0:
        return None
    if fd == 0 and td == 0:
        return 0.0
    return (td - fd) / fd


def _is_cadence_anomaly(packument: dict[str, Any], from_version: str, to_version: str) -> bool:
    """True when the from→to publish window is unusually fast vs package history.

    Requires **all** of:

    (a) ``new_gap < 0.3 × median`` of up to the 10 consecutive inter-release gaps
        immediately preceding ``from_version`` in the publish timeline.
    (b) At least **5** versions published strictly before ``to_version``
        (insufficient history → no flag).
    (c) ``new_gap < 7`` days (absolute floor — weekly-ish cadences are not flagged
        on ratio alone).

    ``new_gap`` is whole days from ``from_version`` publish time to ``to_version``
    publish time.
    """
    events = _published_events(packument)
    idx_from = next((i for i, (_, vk) in enumerate(events) if vk == from_version), None)
    idx_to = next((i for i, (_, vk) in enumerate(events) if vk == to_version), None)
    if idx_from is None or idx_to is None or idx_from >= idx_to:
        return False

    if idx_to < 5:
        return False

    new_gap_days = (events[idx_to][0] - events[idx_from][0]).days
    if new_gap_days >= 7:
        return False

    gaps_before: list[int] = []
    for i in range(1, idx_from + 1):
        gaps_before.append((events[i][0] - events[i - 1][0]).days)
    prior = gaps_before[-10:] if len(gaps_before) > 10 else gaps_before
    if not prior:
        return False

    med = statistics.median(prior)
    if med <= 0:
        return False

    return new_gap_days < 0.3 * med


def fetch_delta(
    cache: Cache,
    package: str,
    from_version: str,
    to_version: str,
) -> TrustDelta:
    """Build a :class:`~arguss.core.models.TrustDelta` from two snapshots.

    Fetches snapshots for ``from_version`` and ``to_version``, then computes the
    delta. Snapshots follow Branch 1 cache policy (24h TTL); cache hits avoid
    extra registry traffic.

    Raises :exc:`TrustClientError` if either version is missing from the registry.
    """
    from_snap = fetch_snapshot(cache, package, from_version)
    to_snap = fetch_snapshot(cache, package, to_version)

    from_set = set(from_snap.maintainer_logins)
    to_set = set(to_snap.maintainer_logins)
    maintainers_added = tuple(sorted(to_set - from_set))
    maintainers_removed = tuple(sorted(from_set - to_set))
    intersection = from_set & to_set
    n_from = len(from_snap.maintainer_logins)
    ownership_transferred = n_from > 0 and len(intersection) < 0.5 * n_from

    days_between_publishes = (to_snap.published_at - from_snap.published_at).days

    with TrustRegistryClient(cache) as client:
        packument = client.fetch_packument(package)
    publish_cadence_anomaly = _is_cadence_anomaly(packument, from_version, to_version)

    weekly_downloads_change_pct = _weekly_downloads_change_pct(from_snap, to_snap)

    flags: list[TrustFlag] = []
    if ownership_transferred:
        flags.append(TrustFlag.OWNERSHIP_TRANSFER)
    if len(maintainers_added) > 0:
        flags.append(TrustFlag.NEW_MAINTAINER)
    if publish_cadence_anomaly:
        flags.append(TrustFlag.CADENCE_ANOMALY)
    if weekly_downloads_change_pct is not None and weekly_downloads_change_pct < -0.5:
        flags.append(TrustFlag.DOWNLOAD_COLLAPSE)

    flags_tuple = tuple(sorted(flags, key=lambda f: f.value))
    safe = len(flags_tuple) == 0

    return TrustDelta(
        package=package,
        from_version=from_version,
        to_version=to_version,
        maintainers_added=maintainers_added,
        maintainers_removed=maintainers_removed,
        ownership_transferred=ownership_transferred,
        days_between_publishes=days_between_publishes,
        publish_cadence_anomaly=publish_cadence_anomaly,
        weekly_downloads_change_pct=weekly_downloads_change_pct,
        flags=flags_tuple,
        safe_to_auto_merge=safe,
    )


def _trust_severity_from_subscore(subscore: int) -> Severity:
    if subscore >= 60:
        return "high"
    if subscore >= 30:
        return "medium"
    return "low"


def _finding_from_snapshot(dep: Dependency, snap: TrustSnapshot) -> Finding:
    desc = (
        f"npm trust subscore={snap.subscore} maintainers={snap.maintainer_count} "
        f"typosquat_distance={snap.typosquat_distance} weekly_downloads={snap.weekly_downloads}"
    )
    return Finding(
        dependency=dep,
        lens="trust",
        severity=_trust_severity_from_subscore(snap.subscore),
        score=float(snap.subscore),
        title=f"Trust profile: {dep.name}@{dep.version}",
        description=desc,
        remediation="Review maintainer history and release cadence before upgrading.",
        source_url=f"https://www.npmjs.com/package/{dep.name}",
    )


class TrustLens:
    """Scans dependencies for package trust signals via npm snapshots."""

    def __init__(self, cache: Cache) -> None:
        self._cache = cache

    def scan(self, deps: list[Dependency]) -> LensScore:
        """Aggregate per-dependency trust subscores (top-N mean, N=10)."""
        if not deps:
            return LensScore(lens="trust", score=0.0, findings=[])

        snapshots: list[tuple[Dependency, TrustSnapshot]] = []
        failed = 0
        for dep in deps:
            try:
                snap = fetch_snapshot(
                    self._cache,
                    dep.name,
                    dep.version,
                    include_scorecard=dep.direct,
                )
                snapshots.append((dep, snap))
            except TrustClientError as e:
                failed += 1
                _LOG.warning(
                    "trust snapshot failed for %s@%s: %s",
                    dep.name,
                    dep.version,
                    e,
                )

        if not snapshots:
            _LOG.warning("trust lens: 0 deps scored, %s failed.", failed)
            return LensScore(lens="trust", score=0.0, findings=[])

        direct_snapshots = [(d, s) for d, s in snapshots if d.direct]
        lens_score_val = aggregate_trust_subscores(
            [s.subscore for _, s in direct_snapshots],
        )

        findings = [_finding_from_snapshot(dep, snap) for dep, snap in snapshots]

        if failed:
            _LOG.warning("trust lens: %s deps scored, %s failed.", len(snapshots), failed)
        else:
            _LOG.info("trust lens: %s deps scored, %s failed.", len(snapshots), failed)

        return LensScore(
            lens="trust",
            score=float(round(lens_score_val, 2)),
            findings=findings,
        )
