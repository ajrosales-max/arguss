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
from arguss.lenses._osv_client import OsvClient
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
            latest_version: str | None = None
            latest_vulnerable: int | None = None
            latest_advisories_json: str | None = None

            if latest:
                packument = registry.fetch_packument(name)
                latest_version = _latest_version_from_packument(packument)
                if latest_version:
                    vuln_ids = osv.query_single(name, latest_version)
                    advisories = [osv.fetch_vuln(vid) for vid in vuln_ids]
                    latest_vulnerable = 1 if vuln_ids else 0
                    latest_advisories_json = json.dumps(advisories)
                else:
                    latest_vulnerable = 0
                    latest_advisories_json = json.dumps([])
                if throttle > 0:
                    time.sleep(throttle)

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
