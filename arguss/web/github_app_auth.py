"""GitHub App authentication primitives (JWT + installation tokens).

Additive only: nothing in the app imports this module yet. The existing PAT
path is untouched. Credentials are optional at boot; decode and key load happen
only when auth is actually invoked.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from datetime import UTC, datetime
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

_default_http_client: httpx.Client | None = None


class GitHubAppConfigError(Exception):
    """Raised when GitHub App credentials are missing or cannot be loaded."""


class GitHubAppAuthError(Exception):
    """Raised when a GitHub App auth API call fails."""


@dataclass(frozen=True)
class InstallationAccessToken:
    """Opaque installation access token and its expiry (tz-aware UTC)."""

    token: str
    expires_at: datetime


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
    global _default_http_client
    if _default_http_client is None:
        _default_http_client = httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS)
    return _default_http_client


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
