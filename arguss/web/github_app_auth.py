"""GitHub App authentication primitives (JWT + installation tokens).

Additive only: nothing in the app imports this module yet. The existing PAT
path is untouched. Credentials are optional at boot; decode and key load happen
only when auth is actually invoked.
"""

from __future__ import annotations

import atexit
import base64
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from arguss.settings import settings

_GITHUB_API_BASE = "https://api.github.com"
_HTTP_TIMEOUT_SECONDS = 30.0
_ACCEPT = "application/vnd.github+json"
_API_VERSION = "2022-11-28"
_REFRESH_SKEW_SECONDS = 300

_client_lock = threading.Lock()
_default_http_client: httpx.Client | None = None

_token_locks: dict[int, threading.Lock] = {}
_token_locks_guard = threading.Lock()


class GitHubAppConfigError(Exception):
    """Raised when GitHub App credentials are missing or cannot be loaded."""


class GitHubAppAuthError(Exception):
    """Raised when a GitHub App auth API call fails."""


@dataclass(frozen=True)
class InstallationAccessToken:
    """Opaque installation access token and its expiry (tz-aware UTC)."""

    token: str
    expires_at: datetime


# Default-scope installation tokens only (scoped mints bypass this cache).
_token_cache: dict[int, InstallationAccessToken] = {}


def load_github_app_private_key(
    *,
    app_id: str | None = None,
    private_key_b64: str | None = None,
) -> tuple[str, RSAPrivateKey]:
    """Return ``(app_id, private_key)`` after validating and decoding config.

    Reads from ``settings`` when arguments are omitted. Decode and PEM load are
    deferred until this function is called — never at import time.

    Raises:
        GitHubAppConfigError: If either credential is missing, base64 is
            invalid, or the decoded content is not a usable PEM private key.
    """
    resolved_app_id = app_id if app_id is not None else settings.github_app_id
    resolved_b64 = (
        private_key_b64 if private_key_b64 is not None else settings.github_app_private_key_b64
    )

    if not resolved_app_id:
        raise GitHubAppConfigError("ARGUSS_GITHUB_APP_ID is not set; cannot mint a GitHub App JWT")
    if not resolved_b64:
        raise GitHubAppConfigError(
            "ARGUSS_GITHUB_APP_PRIVATE_KEY_B64 is not set; cannot mint a GitHub App JWT"
        )

    try:
        pem_bytes = base64.b64decode(resolved_b64, validate=True)
    except Exception as exc:
        raise GitHubAppConfigError("ARGUSS_GITHUB_APP_PRIVATE_KEY_B64 is not valid base64") from exc

    try:
        key = load_pem_private_key(pem_bytes, password=None)
    except Exception as exc:
        raise GitHubAppConfigError(
            "ARGUSS_GITHUB_APP_PRIVATE_KEY_B64 does not contain a valid PEM private key"
        ) from exc

    if not isinstance(key, RSAPrivateKey):
        raise GitHubAppConfigError("ARGUSS_GITHUB_APP_PRIVATE_KEY_B64 must be an RSA private key")

    return resolved_app_id, key


def mint_github_app_jwt() -> str:
    """Mint a short-lived RS256 JWT for authenticating as the GitHub App.

    Claims follow GitHub's App JWT rules: ``iss`` is the app id, ``iat`` is
    now minus 60s (clock-skew buffer), and ``exp`` is now plus 600s (10-minute
    maximum).

    Raises:
        GitHubAppConfigError: If app id or private key config is missing or
            invalid. Never signs a token with a missing issuer.
    """
    if not settings.github_app_id:
        raise GitHubAppConfigError("ARGUSS_GITHUB_APP_ID is not set; cannot mint a GitHub App JWT")

    app_id, private_key = load_github_app_private_key()
    now = int(time.time())
    payload = {
        "iss": app_id,
        "iat": now - 60,
        "exp": now + 600,
    }
    return jwt.encode(payload, private_key, algorithm="RS256")


def _get_default_http_client() -> httpx.Client:
    """Return the shared sync httpx client, creating it lazily.

    The client is reused across mint/refresh calls and closed via
    ``close_default_http_client`` (also registered with ``atexit``) so sockets
    are not leaked at process exit.
    """
    global _default_http_client
    with _client_lock:
        if _default_http_client is None or _default_http_client.is_closed:
            _default_http_client = httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS)
        return _default_http_client


def close_default_http_client() -> None:
    """Close the module-managed httpx client if open. Safe to call repeatedly."""
    global _default_http_client
    with _client_lock:
        if _default_http_client is not None:
            _default_http_client.close()
            _default_http_client = None


atexit.register(close_default_http_client)


def _parse_expires_at(raw: str) -> datetime:
    """Parse GitHub's ``expires_at`` into a timezone-aware UTC datetime."""
    normalized = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def fetch_installation_access_token(
    installation_id: int,
    *,
    permissions: dict[str, str] | None = None,
    repository_ids: list[int] | None = None,
    http_client: httpx.Client | None = None,
) -> InstallationAccessToken:
    """Exchange an app JWT for a short-lived installation access token.

    POSTs to ``/app/installations/{installation_id}/access_tokens``. Optional
    ``permissions`` and ``repository_ids`` are sent in the JSON body only when
    provided (least-privilege scoping). When both are omitted, no body is sent
    and GitHub returns the installation's full grant.

    The token string is treated as opaque — no length assumptions.

    Raises:
        GitHubAppConfigError: If App credentials are missing/invalid (via JWT mint).
        GitHubAppAuthError: If the GitHub API returns a non-2xx response or
            the payload cannot be parsed.
    """
    app_jwt = mint_github_app_jwt()
    headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": _ACCEPT,
        "X-GitHub-Api-Version": _API_VERSION,
    }
    url = f"{_GITHUB_API_BASE}/app/installations/{installation_id}/access_tokens"

    body: dict[str, Any] = {}
    if permissions is not None:
        body["permissions"] = permissions
    if repository_ids is not None:
        body["repository_ids"] = repository_ids

    client = http_client if http_client is not None else _get_default_http_client()
    post_kwargs: dict[str, Any] = {"headers": headers}
    if body:
        post_kwargs["json"] = body

    try:
        response = client.post(url, **post_kwargs)
    except httpx.HTTPError as exc:
        raise GitHubAppAuthError(
            f"GitHub installation token request failed for installation {installation_id}"
        ) from exc

    if response.status_code < 200 or response.status_code >= 300:
        raise GitHubAppAuthError(
            "GitHub installation token request failed for installation "
            f"{installation_id}: HTTP {response.status_code}"
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise GitHubAppAuthError(
            f"GitHub installation token response was not valid JSON "
            f"for installation {installation_id}"
        ) from exc

    if not isinstance(payload, dict):
        raise GitHubAppAuthError(
            f"GitHub installation token response had unexpected shape "
            f"for installation {installation_id}"
        )

    token = payload.get("token")
    expires_at_raw = payload.get("expires_at")
    if not isinstance(token, str) or not token:
        raise GitHubAppAuthError(
            f"GitHub installation token response missing token for installation {installation_id}"
        )
    if not isinstance(expires_at_raw, str) or not expires_at_raw:
        raise GitHubAppAuthError(
            f"GitHub installation token response missing expires_at "
            f"for installation {installation_id}"
        )

    try:
        expires_at = _parse_expires_at(expires_at_raw)
    except ValueError as exc:
        raise GitHubAppAuthError(
            f"GitHub installation token response had invalid expires_at "
            f"for installation {installation_id}"
        ) from exc

    return InstallationAccessToken(token=token, expires_at=expires_at)


def _lock_for_installation(installation_id: int) -> threading.Lock:
    with _token_locks_guard:
        lock = _token_locks.get(installation_id)
        if lock is None:
            lock = threading.Lock()
            _token_locks[installation_id] = lock
        return lock


def _token_is_fresh(cached: InstallationAccessToken, *, now: datetime) -> bool:
    """True if ``now`` is still more than 300s before ``expires_at`` (both tz-aware)."""
    refresh_deadline = cached.expires_at - timedelta(seconds=_REFRESH_SKEW_SECONDS)
    return now < refresh_deadline


def clear_installation_token_cache() -> None:
    """Drop all cached default-scope installation tokens. Intended for tests."""
    with _token_locks_guard:
        _token_cache.clear()


def drop_installation_token_cache(installation_id: int) -> None:
    """Drop the cached default-scope token for one installation, if present."""
    with _token_locks_guard:
        _token_cache.pop(installation_id, None)


def installation_exists(
    installation_id: int,
    *,
    http_client: httpx.Client | None = None,
) -> bool:
    """Return True if the App installation is live; False if GitHub says it is gone.

    Fresh app-JWT ``GET /app/installations/{installation_id}``. Does not read
    or write the installation-token cache (a cached mint must not mask an
    uninstall).

    Returns:
        True on HTTP 2xx; False on HTTP 404 (installation deleted / unknown).

    Raises:
        GitHubAppConfigError: If App credentials are missing/invalid (via JWT).
        GitHubAppAuthError: On network failure or any non-2xx other than 404.
            Callers must not treat this as "gone" or wipe a valid session —
            prefer leaving the session intact and letting a later mint fail
            legibly.
    """
    app_jwt = mint_github_app_jwt()
    headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": _ACCEPT,
        "X-GitHub-Api-Version": _API_VERSION,
    }
    url = f"{_GITHUB_API_BASE}/app/installations/{installation_id}"
    client = http_client if http_client is not None else _get_default_http_client()

    try:
        response = client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        raise GitHubAppAuthError(
            f"GitHub installation liveness check failed for installation {installation_id}"
        ) from exc

    if response.status_code == 404:
        return False
    if 200 <= response.status_code < 300:
        return True
    raise GitHubAppAuthError(
        "GitHub installation liveness check failed for installation "
        f"{installation_id}: HTTP {response.status_code}"
    )


def get_installation_access_token(
    installation_id: int,
    *,
    permissions: dict[str, str] | None = None,
    repository_ids: list[int] | None = None,
    http_client: httpx.Client | None = None,
) -> str:
    """Return a valid installation access token, caching default-scope mints.

    Default-scope tokens (no ``permissions`` / ``repository_ids``) are cached
    per ``installation_id`` and reused until within 300s of ``expires_at``.
    Explicitly scoped requests always mint fresh and do not update the cache.

    Concurrent cold-cache / refresh callers for the same installation share a
    per-id ``threading.Lock`` so only one mint runs.
    """
    # Scoped mints: least-privilege one-shots — never share the default-scope cache.
    if permissions is not None or repository_ids is not None:
        return fetch_installation_access_token(
            installation_id,
            permissions=permissions,
            repository_ids=repository_ids,
            http_client=http_client,
        ).token

    lock = _lock_for_installation(installation_id)
    with lock:
        now = datetime.now(UTC)
        cached = _token_cache.get(installation_id)
        if cached is not None and _token_is_fresh(cached, now=now):
            return cached.token

        fresh = fetch_installation_access_token(
            installation_id,
            http_client=http_client,
        )
        _token_cache[installation_id] = fresh
        return fresh.token


_OAUTH_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
_USER_INSTALLATIONS_URL = f"{_GITHUB_API_BASE}/user/installations"
_USER_INSTALLATIONS_PER_PAGE = 100
_USER_INSTALLATIONS_MAX_PAGES = 10


def exchange_oauth_code_for_user_token(
    code: str,
    *,
    http_client: httpx.Client | None = None,
) -> str:
    """Exchange an OAuth ``code`` for a short-lived user access token.

    POSTs to ``https://github.com/login/oauth/access_token`` (github.com, not the
    REST API host). Returns only the ``access_token`` string — never the refresh
    token. The caller must treat the token as transient and discard it after use.

    Raises:
        GitHubAppConfigError: If OAuth client id/secret Settings are missing.
        GitHubAppAuthError: On HTTP failure, non-2xx, or a JSON body with an
            ``error`` field (GitHub may return HTTP 200 with ``error``).
    """
    client_id = settings.github_app_client_id
    client_secret = settings.github_app_client_secret
    if not client_id:
        raise GitHubAppConfigError(
            "ARGUSS_GITHUB_APP_CLIENT_ID is not set; cannot exchange OAuth code"
        )
    if not client_secret:
        raise GitHubAppConfigError(
            "ARGUSS_GITHUB_APP_CLIENT_SECRET is not set; cannot exchange OAuth code"
        )

    client = http_client if http_client is not None else _get_default_http_client()
    try:
        response = client.post(
            _OAUTH_ACCESS_TOKEN_URL,
            headers={"Accept": "application/json"},
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
            },
        )
    except httpx.HTTPError as exc:
        raise GitHubAppAuthError("GitHub OAuth token exchange request failed") from exc

    if response.status_code < 200 or response.status_code >= 300:
        raise GitHubAppAuthError(f"GitHub OAuth token exchange failed: HTTP {response.status_code}")

    try:
        payload = response.json()
    except ValueError as exc:
        raise GitHubAppAuthError("GitHub OAuth token exchange returned invalid JSON") from exc

    if not isinstance(payload, dict):
        raise GitHubAppAuthError("GitHub OAuth token exchange returned unexpected JSON")

    if "error" in payload:
        # Do not include token material; error/description are safe to surface.
        err = payload.get("error")
        raise GitHubAppAuthError(f"GitHub OAuth token exchange failed: {err}")

    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise GitHubAppAuthError("GitHub OAuth token exchange response missing access_token")

    return access_token


def user_can_access_installation(
    user_token: str,
    installation_id: int,
    *,
    http_client: httpx.Client | None = None,
) -> bool:
    """Return True if ``installation_id`` is among the user's App installations.

    GETs ``/user/installations`` with the transient user token. Follows GitHub
    ``Link: rel="next"`` pagination up to ``_USER_INSTALLATIONS_MAX_PAGES`` pages
    (``per_page=100``) so a large installation list is not truncated to page 1.
    """
    client = http_client if http_client is not None else _get_default_http_client()
    headers = {
        "Authorization": f"Bearer {user_token}",
        "Accept": _ACCEPT,
        "X-GitHub-Api-Version": _API_VERSION,
    }
    url: str | None = _USER_INSTALLATIONS_URL
    params: dict[str, str] | None = {"per_page": str(_USER_INSTALLATIONS_PER_PAGE)}

    for _ in range(_USER_INSTALLATIONS_MAX_PAGES):
        if url is None:
            break
        try:
            response = client.get(url, headers=headers, params=params)
        except httpx.HTTPError as exc:
            raise GitHubAppAuthError(
                "GitHub user installations request failed during ownership check"
            ) from exc

        if response.status_code < 200 or response.status_code >= 300:
            raise GitHubAppAuthError(
                "GitHub user installations request failed during ownership check: "
                f"HTTP {response.status_code}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise GitHubAppAuthError(
                "GitHub user installations response was not valid JSON"
            ) from exc

        if not isinstance(payload, dict):
            raise GitHubAppAuthError("GitHub user installations response had unexpected shape")

        installations = payload.get("installations")
        if not isinstance(installations, list):
            raise GitHubAppAuthError(
                "GitHub user installations response missing installations list"
            )

        for item in installations:
            if not isinstance(item, dict):
                continue
            raw_id = item.get("id")
            if isinstance(raw_id, int) and raw_id == installation_id:
                return True
            # Defensive: some payloads may stringify ids.
            if isinstance(raw_id, str) and raw_id.isdigit() and int(raw_id) == installation_id:
                return True

        next_url = _next_link_url(response.headers.get("Link"))
        url = next_url
        params = None  # next Link already includes query string

    return False


def _next_link_url(link_header: str | None) -> str | None:
    """Parse GitHub's Link header for ``rel="next"``."""
    if not link_header:
        return None
    for part in link_header.split(","):
        section = part.strip()
        if 'rel="next"' not in section and "rel=next" not in section:
            continue
        if section.startswith("<") and ">" in section:
            return section[1 : section.index(">")]
    return None
