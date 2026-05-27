"""HTTP Basic Auth for demo-period gating.

If settings.demo_password is None/empty, auth is a no-op. Useful for local
development. If set (typically via ARGUSS_DEMO_PASSWORD env var in production),
every route depending on this function requires Basic credentials.
"""

from __future__ import annotations

import secrets

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from arguss.settings import settings

_security = HTTPBasic(auto_error=False)
_basic_credentials = Depends(_security)


def require_demo_auth(
    credentials: HTTPBasicCredentials | None = _basic_credentials,
) -> None:
    """Dependency that enforces Basic Auth when demo_password is configured.

    No-op when demo_password is unset (local dev). Raises 401 with
    WWW-Authenticate when configured but credentials are missing or wrong.
    """
    if not settings.demo_password:
        return  # auth disabled

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": 'Basic realm="Arguss"'},
        )

    ok_user = secrets.compare_digest(credentials.username, settings.demo_username)
    ok_pass = secrets.compare_digest(credentials.password, settings.demo_password)
    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": 'Basic realm="Arguss"'},
        )
