"""Client for the OSV.dev API.

OSV.dev (Open Source Vulnerabilities) is a free, well-maintained vulnerability
database aggregating from NVD, GHSA, PyPA, and others.

API docs: https://osv.dev/docs/

Endpoints used:
- POST /v1/query       : look up vulnerability IDs for one package+version
- POST /v1/querybatch : batched package+version lookups
- GET  /v1/vulns/{id} : full vulnerability record by ID

All responses are cached via the SQLite Cache. Single and batch query results
use a 24h TTL; full vuln records use 7 days.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import quote

import httpx

from arguss.core.cache import Cache
from arguss.core.models import Dependency
from arguss.settings import settings

# Default public API; settings.osv_api_base overrides in tests / custom deploys.
OSV_API_DEFAULT = "https://api.osv.dev"

# Per-request timeouts: batch can be slower when OSV is busy.
OSV_TIMEOUT_SINGLE = httpx.Timeout(10.0, connect=5.0)
OSV_TIMEOUT_BATCH = httpx.Timeout(15.0, connect=5.0)

# OSV /v1/querybatch has a per-request limit (~1000). Use a conservative
# chunk size that stays comfortably under any plausible limit.
OSV_BATCH_CHUNK_SIZE = 500

_ARGUSS_VERSION = "0.1.0"
OSV_USER_AGENT = f"arguss/{_ARGUSS_VERSION} (https://github.com/ajrosales-max/arguss)"

_VULN_RECORD_TTL_HOURS = 24 * 7


class OsvError(Exception):
    """Raised when OSV API calls fail in a way the lens should report."""


def _parse_osv_json(resp: httpx.Response, context: str) -> dict[str, Any]:
    """Parse a JSON object from an OSV response body."""
    try:
        parsed: Any = resp.json()
    except json.JSONDecodeError as e:
        raise OsvError(f"OSV returned invalid JSON ({context}): {e}") from e
    if not isinstance(parsed, dict):
        raise OsvError(
            f"OSV returned unexpected JSON root type ({context}): {type(parsed).__name__}"
        )
    return parsed


class OsvClient:
    """Client for the OSV.dev vulnerability database."""

    def __init__(
        self,
        cache: Cache,
        http_client: httpx.Client | None = None,
        api_base: str | None = None,
    ) -> None:
        self.cache = cache
        self.api_base = (api_base or settings.osv_api_base or OSV_API_DEFAULT).rstrip("/")
        self._http = http_client or httpx.Client(
            timeout=OSV_TIMEOUT_SINGLE,
            follow_redirects=True,
            headers={"User-Agent": OSV_USER_AGENT},
        )

    def query_single(self, name: str, version: str, ecosystem: str = "npm") -> list[str]:
        """Query OSV for a single package+version. Returns vulnerability IDs.

        Uses POST /v1/query. Results are cached for 24 hours.
        """
        cache_key = f"single:{ecosystem}:{name}:{version}"
        cached = self.cache.get_api_response("osv", cache_key)
        if cached is not None:
            return list(cached.get("ids", []))

        payload: dict[str, Any] = {
            "package": {"ecosystem": ecosystem, "name": name},
            "version": version,
        }
        url = f"{self.api_base}/v1/query"
        try:
            resp = self._http.post(url, json=payload, timeout=OSV_TIMEOUT_SINGLE)
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise OsvError(f"OSV API call failed for {name}@{version}: {e}") from e

        data = _parse_osv_json(resp, f"query {name}@{version}")
        vuln_ids = [
            str(v["id"]) for v in data.get("vulns", []) if isinstance(v, dict) and "id" in v
        ]
        self.cache.set_api_response(
            "osv",
            cache_key,
            {"ids": vuln_ids},
            ttl_hours=settings.cache_ttl_hours,
        )
        return vuln_ids

    def fetch_vuln(self, vuln_id: str) -> dict[str, Any]:
        """Fetch a full vulnerability record by ID via GET /v1/vulns/{id}.

        Cached for 7 days (records change rarely once published).
        """
        cache_key = f"vuln:{vuln_id}"
        cached = self.cache.get_api_response("osv", cache_key)
        if cached is not None:
            return dict(cached)

        safe_id = quote(vuln_id, safe="")
        vuln_url = f"{self.api_base}/v1/vulns/{safe_id}"
        try:
            resp = self._http.get(vuln_url, timeout=OSV_TIMEOUT_SINGLE)
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise OsvError(f"OSV API call failed for vuln {vuln_id}: {e}") from e

        data = _parse_osv_json(resp, f"vuln {vuln_id}")
        self.cache.set_api_response("osv", cache_key, data, ttl_hours=_VULN_RECORD_TTL_HOURS)
        return data

    def query_batch(self, deps: list[Dependency]) -> dict[str, list[dict[str, Any]]]:
        """Query OSV for many dependencies via POST /v1/querybatch.

        Deduplicates by (ecosystem, name, version), fetches unique vuln IDs,
        then loads full records via ``fetch_vuln``. Batch ID map is cached 24h;
        each vuln record uses the 7-day cache in ``fetch_vuln``.

        Returns:
            Mapping ``name@version`` → list of full vulnerability dicts (OSV schema).
        """
        if not deps:
            return {}

        seen: dict[tuple[str, str, str], Dependency] = {}
        for d in deps:
            seen[(d.ecosystem, d.name, d.version)] = d
        unique_deps = list(seen.values())

        batch_cache_key = f"batch:{_hash_query_set(unique_deps)}"
        cached = self.cache.get_api_response("osv", batch_cache_key)
        if cached is not None:
            vuln_id_map: dict[str, list[str]] = {
                k: list(v) if isinstance(v, list) else []
                for k, v in cached.items()
                if isinstance(k, str)
            }
        else:
            batch_url = f"{self.api_base}/v1/querybatch"
            vuln_id_map = {}
            for chunk_start in range(0, len(unique_deps), OSV_BATCH_CHUNK_SIZE):
                chunk = unique_deps[chunk_start : chunk_start + OSV_BATCH_CHUNK_SIZE]
                chunk_queries = [
                    {
                        "package": {"ecosystem": d.ecosystem, "name": d.name},
                        "version": d.version,
                    }
                    for d in chunk
                ]
                chunk_end = chunk_start + len(chunk)
                try:
                    resp = self._http.post(
                        batch_url,
                        json={"queries": chunk_queries},
                        timeout=OSV_TIMEOUT_BATCH,
                    )
                    resp.raise_for_status()
                except httpx.HTTPError as e:
                    raise OsvError(
                        f"OSV batch query failed for deps [{chunk_start}:{chunk_end}]: {e}"
                    ) from e

                body = _parse_osv_json(resp, f"querybatch chunk [{chunk_start}:{chunk_end}]")
                raw_results = body.get("results", [])
                if not isinstance(raw_results, list):
                    raise OsvError(
                        "OSV querybatch response missing a list 'results' "
                        f"(chunk [{chunk_start}:{chunk_end}])"
                    )
                if len(raw_results) != len(chunk):
                    raise OsvError(
                        "OSV querybatch length mismatch "
                        f"(chunk [{chunk_start}:{chunk_end}]): "
                        f"expected {len(chunk)} results, got {len(raw_results)}"
                    )

                for d, r in zip(chunk, raw_results, strict=True):
                    if not isinstance(r, dict):
                        vuln_id_map[f"{d.name}@{d.version}"] = []
                        continue
                    raw_vulns = r.get("vulns", [])
                    ids: list[str] = []
                    if isinstance(raw_vulns, list):
                        for item in raw_vulns:
                            if isinstance(item, dict) and "id" in item:
                                ids.append(str(item["id"]))
                    vuln_id_map[f"{d.name}@{d.version}"] = ids

            self.cache.set_api_response(
                "osv",
                batch_cache_key,
                vuln_id_map,
                ttl_hours=settings.cache_ttl_hours,
            )

        all_ids: set[str] = {vid for ids in vuln_id_map.values() for vid in ids}
        vuln_records: dict[str, dict[str, Any]] = {}
        for vid in all_ids:
            vuln_records[vid] = self.fetch_vuln(vid)

        return {pkg_key: [vuln_records[vid] for vid in ids] for pkg_key, ids in vuln_id_map.items()}

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._http.close()

    def __enter__(self) -> OsvClient:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _hash_query_set(deps: list[Dependency]) -> str:
    """Stable short hash of a dependency set for batch cache keys."""
    fingerprint = sorted((d.ecosystem, d.name, d.version) for d in deps)
    digest = hashlib.sha256(json.dumps(fingerprint).encode()).hexdigest()
    return digest[:16]
