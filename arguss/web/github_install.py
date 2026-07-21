"""GitHub App install + OAuth callback routes (outside demo Basic auth)."""

from __future__ import annotations

import secrets
from typing import Any
from urllib.parse import urlencode, urlparse

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import RedirectResponse

from arguss.settings import settings
from arguss.web.github_app_auth import (
    GitHubAppAuthError,
    GitHubAppConfigError,
    exchange_oauth_code_for_user_token,
    user_can_access_installation,
)

router = APIRouter(tags=["github-app-install"])

# Session keys (Starlette signed cookie session — not wizard_session).
SESSION_OAUTH_STATE_KEY = "github_oauth_state"
SESSION_INSTALLATION_ID_KEY = "github_installation_id"
SESSION_RETURN_PATH_KEY = "github_return_path"

# Where the callback lands when no valid return path survived the round-trip.
DEFAULT_RESUME_REDIRECT = "/scan"


def safe_internal_path(raw: object) -> str | None:
    """Return ``raw`` if it is a same-site path; otherwise ``None``.

    Open-redirect guard for the OAuth return path: accepts only values that
    start with a single "/" (not "//"), carry no scheme or host, and contain
    no backslashes or control characters (which some browsers normalize into
    off-site targets).
    """
    if not isinstance(raw, str) or not raw:
        return None
    if not raw.startswith("/") or raw.startswith("//"):
        return None
    if "\\" in raw or any(ord(ch) < 0x20 for ch in raw):
        return None
    parsed = urlparse(raw)
    if parsed.scheme or parsed.netloc:
        return None
    return raw


def _derive_return_path(request: Request) -> str | None:
    """Intended post-install destination: explicit ``next`` param, else same-host Referer."""
    explicit = request.query_params.get("next")
    if explicit is not None:
        return safe_internal_path(explicit)

    referer = request.headers.get("referer")
    if not referer:
        return None
    parsed = urlparse(referer)
    if parsed.netloc and parsed.netloc != request.url.netloc:
        return None
    path = parsed.path or ""
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return safe_internal_path(path)


def _require_session(request: Request) -> Any:
    """Return ``request.session`` or a clear HTTP error if middleware is absent."""
    try:
        return request.session
    except AssertionError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Session is not configured. Set ARGUSS_SESSION_SECRET so the "
                "GitHub App install flow can store OAuth state."
            ),
        ) from exc


@router.get("/github/install")
def github_install(request: Request) -> RedirectResponse:
    """Start the combined install+authorize flow; store CSRF state in session."""
    slug = settings.github_app_slug
    if not slug:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ARGUSS_GITHUB_APP_SLUG is not set; cannot start GitHub App install",
        )

    session = _require_session(request)
    state = secrets.token_urlsafe(32)
    session[SESSION_OAUTH_STATE_KEY] = state

    return_path = _derive_return_path(request)
    if return_path is not None:
        session[SESSION_RETURN_PATH_KEY] = return_path
    else:
        # Never leave a stale (or rejected) target around to drive a later redirect.
        session.pop(SESSION_RETURN_PATH_KEY, None)

    query = urlencode({"state": state})
    target = f"https://github.com/apps/{slug}/installations/new?{query}"
    return RedirectResponse(url=target, status_code=status.HTTP_302_FOUND)


@router.get("/github/callback")
def github_callback(
    request: Request,
    code: str | None = None,
    installation_id: str | None = None,
    setup_action: str | None = None,
    state: str | None = None,
) -> RedirectResponse:
    """Complete install+authorize: verify state, exchange code, prove ownership."""
    del setup_action  # accepted from GitHub; unused for now
    session = _require_session(request)

    expected_state = session.get(SESSION_OAUTH_STATE_KEY)
    if (
        not state
        or not expected_state
        or not secrets.compare_digest(str(state), str(expected_state))
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or missing OAuth state; restart the GitHub App install",
        )

    # Single-use: clear immediately after a successful match so the nonce cannot replay.
    session.pop(SESSION_OAUTH_STATE_KEY, None)

    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing OAuth code from GitHub",
        )

    if installation_id is None or not str(installation_id).isdigit():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing or non-numeric installation_id from GitHub",
        )
    installation_id_int = int(installation_id)

    try:
        user_token = exchange_oauth_code_for_user_token(code)
    except GitHubAppConfigError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except GitHubAppAuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub OAuth code exchange failed",
        ) from exc

    owned = False
    try:
        owned = user_can_access_installation(user_token, installation_id_int)
    except GitHubAppAuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not verify GitHub App installation ownership",
        ) from exc
    finally:
        # Discard the transient user token; never persist or return it.
        del user_token

    if not owned:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="GitHub App installation is not accessible to the authorizing user",
        )

    session[SESSION_INSTALLATION_ID_KEY] = installation_id_int
    # Single-use resume target; re-validate on the way out (a poisoned session
    # value must never become an off-site redirect).
    stashed = session.pop(SESSION_RETURN_PATH_KEY, None)
    target = safe_internal_path(stashed) or DEFAULT_RESUME_REDIRECT
    return RedirectResponse(url=target, status_code=status.HTTP_302_FOUND)
