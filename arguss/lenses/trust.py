"""Trust signal lens — maintainer health, typosquatting, population signals.

Branch 1 (Week 4): ``fetch_snapshot`` builds :class:`~arguss.core.models.TrustSnapshot`
from the npm registry + downloads API + bundled top-1000 list.

The :class:`TrustLens` scan path remains a placeholder until Branch 2 wiring.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from arguss.core.cache import Cache
from arguss.core.models import Dependency, Finding, LensScore, TrustSnapshot
from arguss.lenses._trust_client import TrustClientError, TrustRegistryClient

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


def fetch_snapshot(cache: Cache, package: str, version: str) -> TrustSnapshot:
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
            subscore=sub,
        )


class TrustLens:
    """Scans dependencies for package trust signals."""

    def scan(self, deps: list[Dependency]) -> LensScore:
        """Return a LensScore for the given dependencies.

        Currently returns hardcoded fake data for skeleton testing.
        """
        if not deps:
            return LensScore(lens="trust", score=0.0, findings=[])

        fake_finding = Finding(
            dependency=deps[0],
            lens="trust",
            severity="medium",
            score=40.0,
            title=f"Single-maintainer package: {deps[0].name}",
            description=(
                "Fake trust signal for skeleton testing. "
                "Will be replaced with real npm registry data in Week 4."
            ),
            remediation="Review maintainer history before upgrading",
            source_url=f"https://www.npmjs.com/package/{deps[0].name}",
        )

        return LensScore(lens="trust", score=40.0, findings=[fake_finding])
