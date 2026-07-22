"""HTTP Basic Auth for the read/dashboard surface.

On/off is settings.require_auth (ARGUSS_REQUIRE_AUTH). demo_password is the
credential only. When require_auth is False, this dependency is a no-op.
When True, every route depending on this function requires Basic credentials.
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
    """Dependency that enforces Basic Auth when require_auth is enabled.

    No-op when require_auth is False (open read surface). Raises 401 with
    WWW-Authenticate when auth is required but credentials are missing or wrong.
    """
    if not settings.require_auth:
        return  # auth disabled

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": 'Basic realm="Arguss"'},
        )

    password = settings.demo_password or ""
    ok_user = secrets.compare_digest(credentials.username, settings.demo_username)
    ok_pass = secrets.compare_digest(credentials.password, password)
    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": 'Basic realm="Arguss"'},
        )
