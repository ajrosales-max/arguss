"""Cache full scan responses for scan-grounded chat lookup."""

from __future__ import annotations

import logging
from typing import Any

from arguss.core.cache import Cache, get_connection, init_db
from arguss.core.models import SCAN_RESPONSE_SCHEMA_VERSION
from arguss.explanations.executive_summary import build_claude_input, cache_key
from arguss.settings import settings

_LOG = logging.getLogger(__name__)

_SCAN_CACHE_SOURCE = "scan_response"
_SCAN_CACHE_TTL_HOURS = 24


def scan_input_hash(scan_result: dict[str, Any]) -> str:
    """Stable hash aligned with executive-summary cache key derivation."""
    return cache_key(build_claude_input(scan_result))


def _get_cache() -> Cache:
    conn = get_connection(settings.db_path)
    init_db(conn)
    return Cache(conn)


def cache_scan_response(scan_result: dict[str, Any]) -> str:
    """Store the assembled scan payload; return the hash for chat lookup."""
    key = scan_input_hash(scan_result)
    try:
        cache = _get_cache()
        cache.set_scan_response(
            key,
            scan_result,
            schema_version=SCAN_RESPONSE_SCHEMA_VERSION,
            ttl_hours=_SCAN_CACHE_TTL_HOURS,
            source=_SCAN_CACHE_SOURCE,
        )
    except Exception as exc:
        _LOG.warning("scan response cache write failed: %s", exc)
    return key


def get_cached_scan_response(scan_input_hash_value: str) -> dict[str, Any] | None:
    """Load a cached scan payload, or None if missing/expired."""
    try:
        cache = _get_cache()
        return cache.get_scan_response(
            scan_input_hash_value,
            expected_schema_version=SCAN_RESPONSE_SCHEMA_VERSION,
            source=_SCAN_CACHE_SOURCE,
        )
    except Exception as exc:
        _LOG.warning("scan response cache read failed: %s", exc)
        return None
