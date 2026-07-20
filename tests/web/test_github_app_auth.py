"""Tests for GitHub App auth config loading (Step 2 primitives)."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from arguss.settings import validate_settings
from arguss.web.github_app_auth import (
    GitHubAppConfigError,
    load_github_app_private_key,
)


def _ephemeral_rsa_pem_b64() -> str:
    """Generate a throwaway RSA key and return its PEM as base64 (never committed)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(pem).decode("ascii")


def test_load_github_app_private_key_decodes_valid_base64_pem() -> None:
    app_id = "123456"
    b64 = _ephemeral_rsa_pem_b64()

    resolved_id, private_key = load_github_app_private_key(app_id=app_id, private_key_b64=b64)

    assert resolved_id == app_id
    assert private_key.key_size == 2048


def test_load_github_app_private_key_missing_app_id_raises() -> None:
    with pytest.raises(GitHubAppConfigError, match="ARGUSS_GITHUB_APP_ID"):
        load_github_app_private_key(app_id=None, private_key_b64=_ephemeral_rsa_pem_b64())


def test_load_github_app_private_key_missing_key_raises() -> None:
    with pytest.raises(GitHubAppConfigError, match="ARGUSS_GITHUB_APP_PRIVATE_KEY_B64"):
        load_github_app_private_key(app_id="123456", private_key_b64=None)


def test_load_github_app_private_key_malformed_base64_raises() -> None:
    with pytest.raises(GitHubAppConfigError, match="not valid base64"):
        load_github_app_private_key(
            app_id="123456",
            private_key_b64="!!!not-base64!!!",
        )


def test_load_github_app_private_key_non_pem_content_raises() -> None:
    junk_b64 = base64.b64encode(b"this is not a PEM private key").decode("ascii")
    with pytest.raises(GitHubAppConfigError, match="valid PEM private key"):
        load_github_app_private_key(app_id="123456", private_key_b64=junk_b64)


def test_arguss_imports_with_app_vars_unset() -> None:
    """App boot must succeed when GitHub App env vars are absent."""
    import arguss  # noqa: F401
    import arguss.settings as settings_mod
    import arguss.web.github_app_auth as auth_mod

    assert settings_mod.settings.github_app_id is None or isinstance(
        settings_mod.settings.github_app_id, str
    )
    # Module import itself must not raise even if settings fields are None.
    assert auth_mod.GitHubAppConfigError is GitHubAppConfigError


def test_validate_settings_passes_with_app_vars_unset() -> None:
    # validate_settings must not require GitHub App credentials.
    validate_settings(require_ai=False)
