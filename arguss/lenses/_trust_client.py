"""HTTP client for the npm registry and npm download metrics API.

Mirrors :mod:`arguss.lenses._osv_client` structurally: httpx, configurable base
URLs, SQLite cache via :class:`arguss.core.cache.Cache`, and typed errors.

Endpoints:
- ``GET https://registry.npmjs.org/{encodedPackage}`` — full packument (JSON)
- ``GET https://api.npmjs.org/downloads/point/last-week/{encodedPackage}`` —
  last-week download count

The registry requires a recognizable ``User-Agent`` (otherwise 405).
"""

from __future__ import annotations

import json
import time
from typing import Any, cast
from urllib.parse import quote

import httpx

from arguss.core.cache import Cache
from arguss.settings import settings

NPM_REGISTRY_DEFAULT = "https://registry.npmjs.org"
NPM_DOWNLOADS_API_DEFAULT = "https://api.npmjs.org"

# Packuments can be large; allow a generous read window.
TRUST_TIMEOUT_PACKUMENT = httpx.Timeout(10.0, connect=5.0)
TRUST_TIMEOUT_DOWNLOADS = httpx.Timeout(5.0, connect=5.0)

_MAX_ATTEMPTS = 3
_RETRY_STATUSES = frozenset({429, 502, 503, 504})

# ConnectTimeout is not a subclass of ConnectError; include explicitly for retries.
_TRANSIENT_HTTPX_ERRORS = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    httpx.RemoteProtocolError,
)

_TRUST_ARGUSS_VERSION = "0.1.0"
TRUST_USER_AGENT = f"arguss/{_TRUST_ARGUSS_VERSION} (https://github.com/ajrosales-max/arguss)"

# Cache: same ``api_cache`` table as OSV; source ``npm`` matches migration comment.
_CACHE_SOURCE = "npm"
_PACKUMENT_KEY_PREFIX = "npm:packument:"
_DOWNLOADS_KEY_PREFIX = "npm:downloads:last-week:"


class TrustClientError(Exception):
    """Raised when npm registry or downloads API calls fail."""


def _registry_path_segment(package: str) -> str:
    """Encode package name for URL path (scoped: ``@scope%2Fname``)."""
    return quote(package, safe="@")


def _parse_json_object(resp: httpx.Response, context: str) -> dict[str, Any]:
    """Parse a JSON object from a response body."""
    try:
        parsed: Any = resp.json()
    except json.JSONDecodeError as e:
        raise TrustClientError(
            f"npm returned invalid JSON ({context}, package in request): {e}"
        ) from e
    if not isinstance(parsed, dict):
        raise TrustClientError(
            f"npm returned unexpected JSON root type ({context}): {type(parsed).__name__}"
        )
    return cast(dict[str, Any], parsed)


def _streaming_get_with_retries(
    client: httpx.Client,
    url: str,
    *,
    timeout: httpx.Timeout,
    context: str,
    package: str,
) -> tuple[int, bytes]:
    """Stream GET body to bytes with retries on transient HTTP or transport errors."""
    for attempt in range(_MAX_ATTEMPTS):
        try:
            with client.stream("GET", url, timeout=timeout) as resp:
                status = resp.status_code
                body = resp.read()
                if status in _RETRY_STATUSES and attempt < _MAX_ATTEMPTS - 1:
                    time.sleep(0.4 * (2**attempt))
                    continue
                return status, body
        except _TRANSIENT_HTTPX_ERRORS as e:
            if attempt < _MAX_ATTEMPTS - 1:
                time.sleep(0.4 * (2**attempt))
                continue
            raise TrustClientError(f"npm API network error ({context}) for {package!r}: {e}") from e
    raise TrustClientError(f"npm API failed ({context}) for {package!r}: exhausted retries")


def _request_with_retries(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    timeout: httpx.Timeout,
    context: str,
    package: str,
) -> httpx.Response:
    """Perform an HTTP request with small exponential backoff on transient errors."""
    last_exc: BaseException | None = None
    last_resp: httpx.Response | None = None
    for attempt in range(_MAX_ATTEMPTS):
        try:
            resp = client.request(method, url, timeout=timeout)
            if resp.status_code in _RETRY_STATUSES and attempt < _MAX_ATTEMPTS - 1:
                resp.read()
                time.sleep(0.4 * (2**attempt))
                last_resp = resp
                continue
            return resp
        except _TRANSIENT_HTTPX_ERRORS as e:
            last_exc = e
            if attempt < _MAX_ATTEMPTS - 1:
                time.sleep(0.4 * (2**attempt))
                continue
            raise TrustClientError(f"npm API network error ({context}) for {package!r}: {e}") from e

    if last_resp is not None:
        return last_resp
    if last_exc is not None:
        raise TrustClientError(
            f"npm API failed ({context}) for {package!r}: {last_exc}"
        ) from last_exc
    raise TrustClientError(f"npm API failed ({context}) for {package!r}: unknown error")


class TrustRegistryClient:
    """npm registry + downloads API client with SQLite-backed caching."""

    def __init__(
        self,
        cache: Cache,
        http_client: httpx.Client | None = None,
        registry_base: str | None = None,
        downloads_api_base: str | None = None,
    ) -> None:
        self.cache = cache
        reg = registry_base or settings.npm_registry_base or NPM_REGISTRY_DEFAULT
        self.registry_base = reg.rstrip("/")
        dl = downloads_api_base or NPM_DOWNLOADS_API_DEFAULT
        self.downloads_api_base = dl.rstrip("/")
        self._http = http_client or httpx.Client(
            follow_redirects=True,
            headers={"User-Agent": TRUST_USER_AGENT},
        )
        self._owns_client = http_client is None

    def fetch_packument(self, package: str) -> dict[str, Any]:
        """Fetch the full packument from the npm registry.

        Cache TTL: 24 hours (``settings.cache_ttl_hours``).

        Returns the parsed JSON object. Raises :exc:`TrustClientError` on
        4xx/5xx or network failures; messages include ``package``.
        """
        cache_key = f"{_PACKUMENT_KEY_PREFIX}{package}"
        cached = self.cache.get_api_response(_CACHE_SOURCE, cache_key)
        if cached is not None and "packument" in cached:
            return cast(dict[str, Any], cached["packument"])

        path_seg = _registry_path_segment(package)
        url = f"{self.registry_base}/{path_seg}"
        status, body = _streaming_get_with_retries(
            self._http,
            url,
            timeout=TRUST_TIMEOUT_PACKUMENT,
            context="fetch_packument",
            package=package,
        )
        if status == 404:
            raise TrustClientError(f"npm registry: package not found: {package!r}")
        if status >= 400:
            snippet = body[:500].decode("utf-8", errors="replace")
            raise TrustClientError(
                f"npm registry HTTP {status} for {package!r} (fetch_packument): {snippet!r}"
            )

        try:
            parsed: Any = json.loads(body)
        except json.JSONDecodeError as e:
            raise TrustClientError(
                f"npm registry returned invalid JSON (fetch_packument) for {package!r}: {e}"
            ) from e
        if not isinstance(parsed, dict):
            raise TrustClientError(
                f"npm registry returned unexpected JSON root type for {package!r}: "
                f"{type(parsed).__name__}"
            )
        packument = cast(dict[str, Any], parsed)
        self.cache.set_api_response(
            _CACHE_SOURCE,
            cache_key,
            {"packument": packument},
            ttl_hours=settings.cache_ttl_hours,
        )
        return packument

    def fetch_weekly_downloads(self, package: str) -> int | None:
        """Fetch last-week download count from the npm downloads API.

        Cache TTL: 24 hours.

        Returns the download count, ``0`` if the API reports zero downloads,
        or ``None`` if download data is unavailable (e.g. 404).
        """
        cache_key = f"{_DOWNLOADS_KEY_PREFIX}{package}"
        cached = self.cache.get_api_response(_CACHE_SOURCE, cache_key)
        if cached is not None and "downloads" in cached:
            raw = cached.get("downloads")
            if raw is None:
                return None
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise TrustClientError(
                    f"corrupt npm downloads cache for {package!r}: {type(raw).__name__}"
                )
            return int(raw)

        path_seg = _registry_path_segment(package)
        url = f"{self.downloads_api_base}/downloads/point/last-week/{path_seg}"
        resp = _request_with_retries(
            self._http,
            "GET",
            url,
            timeout=TRUST_TIMEOUT_DOWNLOADS,
            context="fetch_weekly_downloads",
            package=package,
        )
        if resp.status_code == 404:
            self.cache.set_api_response(
                _CACHE_SOURCE,
                cache_key,
                {"downloads": None},
                ttl_hours=settings.cache_ttl_hours,
            )
            return None
        if resp.status_code >= 400:
            raise TrustClientError(
                f"npm downloads HTTP {resp.status_code} for {package!r}: {resp.text[:500]!r}"
            )

        data = _parse_json_object(resp, f"downloads {package}")
        raw_downloads = data.get("downloads")
        if raw_downloads is None:
            self.cache.set_api_response(
                _CACHE_SOURCE,
                cache_key,
                {"downloads": None},
                ttl_hours=settings.cache_ttl_hours,
            )
            return None
        if isinstance(raw_downloads, bool) or not isinstance(raw_downloads, (int, float)):
            raise TrustClientError(
                f"npm downloads unexpected 'downloads' type for {package!r}: "
                f"{type(raw_downloads).__name__}"
            )
        count = int(raw_downloads)
        self.cache.set_api_response(
            _CACHE_SOURCE,
            cache_key,
            {"downloads": count},
            ttl_hours=settings.cache_ttl_hours,
        )
        return count

    def close(self) -> None:
        """Close the underlying HTTP client if we own it."""
        if self._owns_client:
            self._http.close()

    def __enter__(self) -> TrustRegistryClient:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
