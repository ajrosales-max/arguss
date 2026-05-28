"""EPSS (Exploit Prediction Scoring System) client.

Fetches per-CVE exploitation probability from FIRST.org.
Batched, cached, fail-soft.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import httpx

from arguss.core.cache import Cache

_LOG = logging.getLogger(__name__)

_EPSS_API_BASE = "https://api.first.org/data/v1/epss"
_EPSS_BATCH_CHUNK_SIZE = 100  # FIRST.org accepts ~100 CVEs per request
_EPSS_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
_EPSS_CACHE_TTL_SECONDS = 60 * 60 * 24  # 24h
_CACHE_SOURCE = "epss"

_TRANSIENT_HTTPX_ERRORS = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.PoolTimeout,
)


@dataclass(frozen=True)
class EpssData:
    """EPSS data for a single CVE."""

    cve_id: str
    epss: float | None  # 0.0-1.0 probability
    percentile: float | None  # 0.0-1.0 rank among all CVEs
    date: str | None  # YYYY-MM-DD freshness


def _cache_key(cve_ids: list[str]) -> str:
    payload = ",".join(cve_ids)
    digest = hashlib.sha256(payload.encode()).hexdigest()
    return f"epss:{digest}"


def _parse_epss_value(raw: Any) -> float | None:
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _row_to_epss_data(row: dict[str, Any]) -> EpssData | None:
    cve = row.get("cve")
    if not isinstance(cve, str) or not cve:
        return None
    return EpssData(
        cve_id=cve,
        epss=_parse_epss_value(row.get("epss")),
        percentile=_parse_epss_value(row.get("percentile")),
        date=row.get("date") if isinstance(row.get("date"), str) else None,
    )


def _parse_response(payload: dict[str, Any]) -> dict[str, EpssData]:
    data = payload.get("data")
    if not isinstance(data, list):
        return {}
    out: dict[str, EpssData] = {}
    for row in data:
        if not isinstance(row, dict):
            continue
        parsed = _row_to_epss_data(row)
        if parsed is not None:
            out[parsed.cve_id] = parsed
    return out


async def _fetch_chunk_http(
    client: httpx.AsyncClient,
    cve_ids: list[str],
    api_base: str,
) -> dict[str, EpssData]:
    cve_param = ",".join(cve_ids)
    url = f"{api_base.rstrip('/')}?cve={cve_param}"
    resp = await client.get(url, timeout=_EPSS_TIMEOUT)
    resp.raise_for_status()
    payload = resp.json()
    if not isinstance(payload, dict):
        return {}
    return _parse_response(payload)


async def _fetch_chunk(
    cve_ids: list[str],
    *,
    cache: Cache | None,
    http_client: httpx.AsyncClient | None,
    api_base: str,
) -> dict[str, EpssData]:
    if not cve_ids:
        return {}

    key = _cache_key(cve_ids)
    if cache is not None:
        cached = cache.get_api_response(_CACHE_SOURCE, key)
        if cached is not None:
            rows = cached.get("rows")
            if isinstance(rows, dict):
                return {
                    cve: EpssData(
                        cve_id=cve,
                        epss=_parse_epss_value(item.get("epss")),
                        percentile=_parse_epss_value(item.get("percentile")),
                        date=item.get("date") if isinstance(item.get("date"), str) else None,
                    )
                    for cve, item in rows.items()
                    if isinstance(item, dict)
                }

    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(follow_redirects=True)
    try:
        parsed = await _fetch_chunk_http(client, cve_ids, api_base)
    except _TRANSIENT_HTTPX_ERRORS as exc:
        _LOG.warning("EPSS chunk fetch failed (transient): %s", exc)
        return {}
    except httpx.HTTPError as exc:
        _LOG.warning("EPSS chunk fetch failed: %s", exc)
        return {}
    finally:
        if owns_client:
            await client.aclose()

    if cache is not None and parsed:
        cache.set_api_response(
            _CACHE_SOURCE,
            key,
            {
                "rows": {
                    cve: {
                        "epss": data.epss,
                        "percentile": data.percentile,
                        "date": data.date,
                    }
                    for cve, data in parsed.items()
                }
            },
            ttl_hours=24,
        )

    return parsed


async def fetch_epss_for_cves(
    cve_ids: Iterable[str],
    *,
    cache: Cache | None = None,
    http_client: httpx.AsyncClient | None = None,
    api_base: str = _EPSS_API_BASE,
) -> dict[str, EpssData]:
    """Fetch EPSS data for a set of CVE IDs. Returns a dict keyed by CVE ID.

    Missing CVEs (not in EPSS database, e.g., reserved-but-unanalyzed) are
    simply absent from the returned dict - not an error.

    Fail-soft: on any HTTP/network failure for a chunk, that chunk is skipped
    and a warning is logged. The caller treats absence as "no EPSS data available."
    """
    unique = sorted({cve for cve in cve_ids if cve})
    if not unique:
        return {}

    result: dict[str, EpssData] = {}
    for start in range(0, len(unique), _EPSS_BATCH_CHUNK_SIZE):
        chunk = unique[start : start + _EPSS_BATCH_CHUNK_SIZE]
        chunk_result = await _fetch_chunk(
            chunk,
            cache=cache,
            http_client=http_client,
            api_base=api_base,
        )
        result.update(chunk_result)
    return result
