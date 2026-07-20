"""GitHub App authentication primitives (JWT + installation tokens).

Additive only: nothing in the app imports this module yet. The existing PAT
path is untouched. Credentials are optional at boot; decode and key load happen
only when auth is actually invoked.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from arguss.settings import settings


class GitHubAppConfigError(Exception):
    """Raised when GitHub App credentials are missing or cannot be loaded."""


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
