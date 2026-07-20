"""Tests for GitHub App auth config, JWT minting, and installation tokens."""

from __future__ import annotations

import base64
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from unittest import mock

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from arguss.settings import settings, validate_settings
from arguss.web.github_app_auth import (
    GitHubAppAuthError,
    GitHubAppConfigError,
    fetch_installation_access_token,
    load_github_app_private_key,
    mint_github_app_jwt,
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


@pytest.fixture
def ephemeral_app_credentials() -> Iterator[tuple[str, str, RSAPublicKey]]:
    """Ephemeral app id + base64 PEM + matching public key (never committed)."""
    private_key: RSAPrivateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    app_id = "424242"
    b64 = base64.b64encode(pem).decode("ascii")
    public_key = private_key.public_key()
    yield app_id, b64, public_key


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


def test_mint_github_app_jwt_claims_and_signature(
    ephemeral_app_credentials: tuple[str, str, RSAPublicKey],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app_id, b64, public_key = ephemeral_app_credentials
    monkeypatch.setattr(settings, "github_app_id", app_id)
    monkeypatch.setattr(settings, "github_app_private_key_b64", b64)

    token = mint_github_app_jwt()
    after = int(time.time())
    claims = jwt.decode(token, public_key, algorithms=["RS256"])

    assert claims["iss"] == app_id
    # iat is now-60 and exp is now+600, so the claim window is 660s; GitHub's
    # 10-minute cap applies to wall-clock exp, not exp-iat.
    assert claims["exp"] - claims["iat"] == 660
    assert claims["iat"] <= after
    assert claims["exp"] <= after + 600
    assert jwt.get_unverified_header(token)["alg"] == "RS256"


def test_mint_github_app_jwt_missing_app_id_raises(
    ephemeral_app_credentials: tuple[str, str, RSAPublicKey],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, b64, _ = ephemeral_app_credentials
    monkeypatch.setattr(settings, "github_app_id", None)
    monkeypatch.setattr(settings, "github_app_private_key_b64", b64)

    with pytest.raises(GitHubAppConfigError, match="ARGUSS_GITHUB_APP_ID"):
        mint_github_app_jwt()


def test_mint_github_app_jwt_missing_private_key_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "github_app_id", "123456")
    monkeypatch.setattr(settings, "github_app_private_key_b64", None)

    with pytest.raises(GitHubAppConfigError, match="ARGUSS_GITHUB_APP_PRIVATE_KEY_B64"):
        mint_github_app_jwt()


# --- Step 4: installation access token fetch ---

_LONG_GHS_TOKEN = "ghs_" + ("x" * 80)  # well over classic 40-char length


def _mock_token_response(
    *,
    token: str = _LONG_GHS_TOKEN,
    expires_at: str = "2026-07-20T21:00:00Z",
    status_code: int = 201,
) -> mock.MagicMock:
    response = mock.MagicMock(spec=httpx.Response)
    response.status_code = status_code
    response.json.return_value = {"token": token, "expires_at": expires_at}
    return response


def test_fetch_installation_access_token_url_headers_and_parse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "arguss.web.github_app_auth.mint_github_app_jwt",
        lambda: "test-app-jwt",
    )
    client = mock.MagicMock(spec=httpx.Client)
    client.post.return_value = _mock_token_response()

    result = fetch_installation_access_token(987654, http_client=client)

    client.post.assert_called_once()
    call_args = client.post.call_args
    assert call_args.args[0] == ("https://api.github.com/app/installations/987654/access_tokens")
    headers = call_args.kwargs["headers"]
    assert headers["Authorization"] == "Bearer test-app-jwt"
    assert headers["Accept"] == "application/vnd.github+json"
    assert headers["X-GitHub-Api-Version"] == "2022-11-28"
    assert "json" not in call_args.kwargs

    assert result.token == _LONG_GHS_TOKEN
    assert len(result.token) > 40
    assert result.expires_at.tzinfo is not None
    assert result.expires_at == datetime(2026, 7, 20, 21, 0, 0, tzinfo=UTC)


def test_fetch_installation_access_token_body_omitted_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "arguss.web.github_app_auth.mint_github_app_jwt",
        lambda: "test-app-jwt",
    )
    client = mock.MagicMock(spec=httpx.Client)
    client.post.return_value = _mock_token_response()

    fetch_installation_access_token(1, http_client=client)

    assert "json" not in client.post.call_args.kwargs


def test_fetch_installation_access_token_body_permissions_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "arguss.web.github_app_auth.mint_github_app_jwt",
        lambda: "test-app-jwt",
    )
    client = mock.MagicMock(spec=httpx.Client)
    client.post.return_value = _mock_token_response()
    permissions = {"contents": "write", "pull_requests": "write"}

    fetch_installation_access_token(1, permissions=permissions, http_client=client)

    assert client.post.call_args.kwargs["json"] == {"permissions": permissions}


def test_fetch_installation_access_token_body_repository_ids_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "arguss.web.github_app_auth.mint_github_app_jwt",
        lambda: "test-app-jwt",
    )
    client = mock.MagicMock(spec=httpx.Client)
    client.post.return_value = _mock_token_response()

    fetch_installation_access_token(1, repository_ids=[11, 22], http_client=client)

    assert client.post.call_args.kwargs["json"] == {"repository_ids": [11, 22]}


def test_fetch_installation_access_token_body_both_scopes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "arguss.web.github_app_auth.mint_github_app_jwt",
        lambda: "test-app-jwt",
    )
    client = mock.MagicMock(spec=httpx.Client)
    client.post.return_value = _mock_token_response()
    permissions = {"metadata": "read"}

    fetch_installation_access_token(
        1,
        permissions=permissions,
        repository_ids=[42],
        http_client=client,
    )

    assert client.post.call_args.kwargs["json"] == {
        "permissions": permissions,
        "repository_ids": [42],
    }


def test_fetch_installation_access_token_long_ghs_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "arguss.web.github_app_auth.mint_github_app_jwt",
        lambda: "test-app-jwt",
    )
    client = mock.MagicMock(spec=httpx.Client)
    client.post.return_value = _mock_token_response(token=_LONG_GHS_TOKEN)

    result = fetch_installation_access_token(1, http_client=client)

    assert result.token == _LONG_GHS_TOKEN
    assert result.token.startswith("ghs_")
    assert len(result.token) > 40


def test_fetch_installation_access_token_non_2xx_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "arguss.web.github_app_auth.mint_github_app_jwt",
        lambda: "test-app-jwt",
    )
    client = mock.MagicMock(spec=httpx.Client)
    client.post.return_value = _mock_token_response(status_code=403)

    with pytest.raises(GitHubAppAuthError, match="HTTP 403"):
        fetch_installation_access_token(1, http_client=client)
