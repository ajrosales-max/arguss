"""OSV vulnerability sweep for the download-ranked top-1000 npm list."""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from arguss.core.cache import Cache, get_connection, init_db
from arguss.core.top_1000_list import load_ranked_top_1000
from arguss.engine.fix_kind import compare_versions
from arguss.lenses._osv_client import OsvClient, OsvError
from arguss.lenses._trust_client import TrustRegistryClient

logger = logging.getLogger(__name__)

_UPSERT_SQL = """
INSERT OR REPLACE INTO top_packages (
    rank, name, historical_advisory_count, historical_advisory_ids,
    latest_version, latest_vulnerable, latest_advisories, swept_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
"""


def _latest_version_from_packument(packument: dict[str, Any]) -> str | None:
    dist_tags = packument.get("dist-tags")
    if not isinstance(dist_tags, dict):
        return None
    latest = dist_tags.get("latest")
    return latest if isinstance(latest, str) and latest else None


def _is_npm_affected_entry(entry: dict[str, Any]) -> bool:
    pkg = entry.get("package")
    return isinstance(pkg, dict) and pkg.get("ecosystem") == "npm"


def _parse_range_events(rng: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    events = rng.get("events")
    if not isinstance(events, list):
        return introduced, fixed, last_affected
    for event in events:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            introduced = str(event["introduced"])
        if "fixed" in event:
            fixed = str(event["fixed"])
        if "last_affected" in event:
            last_affected = str(event["last_affected"])
    return introduced, fixed, last_affected


def _version_is_affected_by_range(
    version: str,
    *,
    introduced: str | None,
    fixed: str | None,
    last_affected: str | None,
) -> bool:
    if introduced is not None:
        cmp = compare_versions(version, introduced)
        if cmp is None or cmp < 0:
            return False
    if fixed is not None:
        cmp = compare_versions(version, fixed)
        if cmp is None or cmp >= 0:
            return False
    if last_affected is not None:
        cmp = compare_versions(version, last_affected)
        if cmp is None or cmp > 0:
            return False
    return True


def _affected_versions_from_entry(entry: dict[str, Any]) -> set[str]:
    """Collect concrete version strings OSV marks affected for one npm affected entry."""
    candidates: set[str] = set()
    versions_list = [
        ver for ver in (entry.get("versions") or []) if isinstance(ver, str) and ver.strip()
    ]
    ranges = entry.get("ranges")
    if not isinstance(ranges, list) or not ranges:
        candidates.update(versions_list)
        return candidates

    for rng in ranges:
        if not isinstance(rng, dict):
            continue
        introduced, fixed, last_affected = _parse_range_events(rng)
        if last_affected and _version_is_affected_by_range(
            last_affected,
            introduced=introduced,
            fixed=fixed,
            last_affected=last_affected,
        ):
            candidates.add(last_affected)
        for ver in versions_list:
            if _version_is_affected_by_range(
                ver,
                introduced=introduced,
                fixed=fixed,
                last_affected=last_affected,
            ):
                candidates.add(ver)

    return candidates


def _advisory_records_for_npm_package(
    records: list[dict[str, Any]], package_name: str
) -> list[dict[str, Any]]:
    trimmed: list[dict[str, Any]] = []
    for record in records:
        affected = record.get("affected")
        if not isinstance(affected, list):
            continue
        npm_affected = [
            entry
            for entry in affected
            if isinstance(entry, dict)
            and _is_npm_affected_entry(entry)
            and isinstance(entry.get("package"), dict)
            and entry["package"].get("name") == package_name
        ]
        if npm_affected:
            trimmed.append({**record, "affected": npm_affected})
    return trimmed


def _version_below_latest(version: str, current_latest: str | None) -> bool:
    if current_latest is None:
        return True
    cmp = compare_versions(version, current_latest)
    return cmp == -1


def _pick_highest_version(versions: set[str]) -> str | None:
    best: str | None = None
    for ver in versions:
        if best is None:
            best = ver
            continue
        cmp = compare_versions(ver, best)
        if cmp is None:
            continue
        if cmp > 0:
            best = ver
    return best


def highest_affected_version(
    advisory_records: list[dict[str, Any]],
    current_latest: str | None,
) -> tuple[str | None, list[str]]:
    """Return the highest npm-affected version below ``current_latest`` and its advisory IDs.

    Walks OSV ``affected[]`` (npm ecosystem only): explicit ``versions[]`` filtered by range
    events, plus ``last_affected`` event values. With ``fixed``, affected means ``< fixed``;
    with ``last_affected``, affected means ``<= last_affected``.
    """
    version_sources: dict[str, set[str]] = {}

    for record in advisory_records:
        advisory_id = record.get("id")
        if not isinstance(advisory_id, str) or not advisory_id:
            continue
        affected = record.get("affected")
        if not isinstance(affected, list):
            continue
        for entry in affected:
            if not isinstance(entry, dict) or not _is_npm_affected_entry(entry):
                continue
            for ver in _affected_versions_from_entry(entry):
                if not _version_below_latest(ver, current_latest):
                    continue
                if compare_versions(ver, ver) is None:
                    continue
                version_sources.setdefault(ver, set()).add(advisory_id)

    if not version_sources:
        return None, []

    peak = _pick_highest_version(set(version_sources))
    if peak is None:
        return None, []

    return peak, sorted(version_sources[peak])


def _fetch_vulns_fail_soft(
    osv: OsvClient,
    vuln_ids: list[str],
    *,
    package_name: str,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for vid in vuln_ids:
        try:
            records.append(osv.fetch_vuln(vid))
        except OsvError:
            logger.warning(
                "top-1000 sweep: OSV fetch failed for %s on %s; skipping",
                vid,
                package_name,
            )
    return records


def run_sweep(
    db_path: Path | str,
    *,
    latest: bool = True,
    throttle: float = 0.25,
    data_dir: Path | None = None,
    osv_client: OsvClient | None = None,
    registry_client: TrustRegistryClient | None = None,
    ranked_packages: list[tuple[int, str]] | None = None,
) -> int:
    """Sweep OSV (and optionally npm latest) for the top-1000 list.

    Pass 1: package-only OSV querybatch for historical advisory IDs.
    Pass 2 (when ``latest=True``): npm packument latest tag + versioned OSV query.

    Returns the number of rows upserted.
    """
    packages = (
        ranked_packages if ranked_packages is not None else load_ranked_top_1000(data_dir=data_dir)
    )
    if not packages:
        logger.warning("top-1000 sweep: no packages loaded")
        return 0

    conn = get_connection(db_path)
    init_db(conn)
    cache = Cache(conn)
    owns_osv = osv_client is None
    owns_registry = registry_client is None
    osv = osv_client or OsvClient(cache=cache)
    registry = registry_client or TrustRegistryClient(cache=cache)

    try:
        names = [name for _rank, name in packages]
        historical_map = osv.query_batch_packages(names)
        swept_at = datetime.now(UTC).isoformat()
        count = 0

        for rank, name in packages:
            hist_ids = historical_map.get(name, [])
            historical_advisories = _fetch_vulns_fail_soft(osv, hist_ids, package_name=name)
            scoped_historical = _advisory_records_for_npm_package(historical_advisories, name)
            latest_version: str | None = None
            latest_vulnerable: int | None = None
            latest_advisories_json: str | None = None

            if latest:
                packument = registry.fetch_packument(name)
                latest_version = _latest_version_from_packument(packument)
                if latest_version:
                    vuln_ids = osv.query_single(name, latest_version)
                    advisories = _fetch_vulns_fail_soft(osv, vuln_ids, package_name=name)
                    latest_vulnerable = 1 if vuln_ids else 0
                    latest_advisories_json = json.dumps(advisories)
                else:
                    latest_vulnerable = 0
                    latest_advisories_json = json.dumps([])
                if throttle > 0:
                    time.sleep(throttle)

            highest_affected_version(scoped_historical, latest_version)

            conn.execute(
                _UPSERT_SQL,
                (
                    rank,
                    name,
                    len(hist_ids),
                    json.dumps(hist_ids),
                    latest_version,
                    latest_vulnerable,
                    latest_advisories_json,
                    swept_at,
                ),
            )
            count += 1

        conn.commit()
        logger.info("top-1000 sweep complete: %d packages", count)
        return count
    finally:
        if owns_osv:
            osv.close()
        if owns_registry:
            registry.close()
        conn.close()
