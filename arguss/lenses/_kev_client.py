"""CISA KEV (Known Exploited Vulnerabilities) client.

Fetches the full KEV catalog from CISA, caches it in-memory and persistently
for 24 hours. Provides a set-based lookup for any CVE ID.

Display-only signal — does not influence fix-confidence or any decision.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx

from arguss.core.cache import Cache

_LOG = logging.getLogger(__name__)

_KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
_KEV_TIMEOUT = httpx.Timeout(15.0, connect=5.0)
_KEV_CACHE_KEY = "kev:catalog"
_CACHE_SOURCE = "kev"

_TRANSIENT_HTTPX_ERRORS = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.PoolTimeout,
)


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    date_added: str | None
    due_date: str | None
    known_ransomware: bool


def _parse_feed_payload(payload: dict[str, Any]) -> dict[str, KevEntry]:
    entries: dict[str, KevEntry] = {}
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return entries
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        cve_id = vuln.get("cveID")
        if not isinstance(cve_id, str) or not cve_id:
            continue
        entries[cve_id] = KevEntry(
            cve_id=cve_id,
            date_added=vuln.get("dateAdded") if isinstance(vuln.get("dateAdded"), str) else None,
            due_date=vuln.get("dueDate") if isinstance(vuln.get("dueDate"), str) else None,
            known_ransomware=vuln.get("knownRansomwareCampaignUse") == "Known",
        )
    return entries


def _parse_cached_catalog(cached: dict[str, Any]) -> dict[str, KevEntry]:
    entries: dict[str, KevEntry] = {}
    rows = cached.get("entries")
    if not isinstance(rows, list):
        return entries
    for row in rows:
        if not isinstance(row, dict):
            continue
        cve_id = row.get("cve_id")
        if not isinstance(cve_id, str) or not cve_id:
            continue
        entries[cve_id] = KevEntry(
            cve_id=cve_id,
            date_added=row.get("date_added") if isinstance(row.get("date_added"), str) else None,
            due_date=row.get("due_date") if isinstance(row.get("due_date"), str) else None,
            known_ransomware=bool(row.get("known_ransomware", False)),
        )
    return entries


def _catalog_to_cache_payload(catalog: dict[str, KevEntry]) -> dict[str, Any]:
    return {
        "entries": [
            {
                "cve_id": entry.cve_id,
                "date_added": entry.date_added,
                "due_date": entry.due_date,
                "known_ransomware": entry.known_ransomware,
            }
            for entry in catalog.values()
        ]
    }


async def fetch_kev_catalog(
    *,
    cache: Cache | None = None,
    http_client: httpx.AsyncClient | None = None,
    feed_url: str = _KEV_FEED_URL,
) -> dict[str, KevEntry]:
    """Fetch the KEV catalog. Returns a dict keyed by CVE ID.

    Fail-soft: on any HTTP/network failure or malformed response, returns an
    empty dict and logs a warning. Callers treat absence as 'not on KEV'.
    """
    if cache is not None:
        cached = cache.get_api_response(_CACHE_SOURCE, _KEV_CACHE_KEY)
        if cached is not None:
            try:
                return _parse_cached_catalog(cached)
            except (KeyError, TypeError, ValueError) as exc:
                _LOG.warning("KEV cache parse failed, refetching: %s", exc)

    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(follow_redirects=True, timeout=_KEV_TIMEOUT)
    try:
        response = await client.get(feed_url)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            return {}
    except _TRANSIENT_HTTPX_ERRORS as exc:
        _LOG.warning("KEV catalog fetch failed (transient): %s", exc)
        return {}
    except httpx.HTTPError as exc:
        _LOG.warning("KEV catalog fetch failed: %s", exc)
        return {}
    except ValueError as exc:
        _LOG.warning("KEV catalog JSON decode failed: %s", exc)
        return {}
    finally:
        if owns_client:
            await client.aclose()

    try:
        catalog = _parse_feed_payload(payload)
    except (KeyError, TypeError) as exc:
        _LOG.warning("KEV catalog parse failed: %s", exc)
        return {}

    if cache is not None and catalog:
        cache.set_api_response(
            _CACHE_SOURCE,
            _KEV_CACHE_KEY,
            _catalog_to_cache_payload(catalog),
            ttl_hours=24,
        )

    return catalog
