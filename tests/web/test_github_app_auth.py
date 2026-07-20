"""Tests for GitHub App auth config, JWT minting, and installation tokens."""

from __future__ import annotations

import base64
import threading
import time
import warnings
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from unittest import mock

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from arguss.settings import settings, validate_settings
from arguss.web import github_app_auth
from arguss.web.github_app_auth import (
    GitHubAppAuthError,
    GitHubAppConfigError,
    InstallationAccessToken,
    clear_installation_token_cache,
    close_default_http_client,
    exchange_oauth_code_for_user_token,
    fetch_installation_access_token,
    get_installation_access_token,
    load_github_app_private_key,
    mint_github_app_jwt,
    user_can_access_installation,
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


# --- Step 5: caching provider ---


@pytest.fixture(autouse=True)
def _reset_installation_token_cache() -> Iterator[None]:
    clear_installation_token_cache()
    yield
    clear_installation_token_cache()
    close_default_http_client()


def test_get_installation_access_token_reuses_cache_inside_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fetch = mock.MagicMock(
        return_value=InstallationAccessToken(
            token="ghs_cached_default",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    monkeypatch.setattr(github_app_auth, "fetch_installation_access_token", fetch)

    first = get_installation_access_token(42)
    second = get_installation_access_token(42)

    assert first == second == "ghs_cached_default"
    assert fetch.call_count == 1


def test_get_installation_access_token_refreshes_within_300s_of_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    near_expiry = InstallationAccessToken(
        token="ghs_old",
        expires_at=datetime.now(UTC) + timedelta(seconds=100),
    )
    refreshed = InstallationAccessToken(
        token="ghs_new",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    github_app_auth._token_cache[7] = near_expiry

    fetch = mock.MagicMock(return_value=refreshed)
    monkeypatch.setattr(github_app_auth, "fetch_installation_access_token", fetch)

    token = get_installation_access_token(7)

    assert token == "ghs_new"
    assert fetch.call_count == 1


def test_get_installation_access_token_scoped_bypasses_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cached = InstallationAccessToken(
        token="ghs_default_cached",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    github_app_auth._token_cache[9] = cached

    fetch = mock.MagicMock(
        return_value=InstallationAccessToken(
            token="ghs_scoped_fresh",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    monkeypatch.setattr(github_app_auth, "fetch_installation_access_token", fetch)

    scoped = get_installation_access_token(9, permissions={"contents": "read"})
    default_again = get_installation_access_token(9)

    assert scoped == "ghs_scoped_fresh"
    assert default_again == "ghs_default_cached"
    assert fetch.call_count == 1
    fetch.assert_called_once_with(
        9,
        permissions={"contents": "read"},
        repository_ids=None,
        http_client=None,
    )
    assert github_app_auth._token_cache[9].token == "ghs_default_cached"


def test_get_installation_access_token_repository_ids_bypasses_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    github_app_auth._token_cache[3] = InstallationAccessToken(
        token="ghs_default",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    fetch = mock.MagicMock(
        return_value=InstallationAccessToken(
            token="ghs_repo_scoped",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    monkeypatch.setattr(github_app_auth, "fetch_installation_access_token", fetch)

    token = get_installation_access_token(3, repository_ids=[100])

    assert token == "ghs_repo_scoped"
    assert fetch.call_count == 1
    assert github_app_auth._token_cache[3].token == "ghs_default"


def test_get_installation_access_token_concurrent_cold_cache_mints_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    call_count = 0
    call_lock = threading.Lock()
    barrier = threading.Barrier(8)

    def slow_fetch(
        installation_id: int,
        *,
        permissions: dict[str, str] | None = None,
        repository_ids: list[int] | None = None,
        http_client: httpx.Client | None = None,
    ) -> InstallationAccessToken:
        nonlocal call_count
        with call_lock:
            call_count += 1
        time.sleep(0.05)
        return InstallationAccessToken(
            token="ghs_concurrent_once",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

    monkeypatch.setattr(github_app_auth, "fetch_installation_access_token", slow_fetch)

    results: list[str] = []
    results_lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        token = get_installation_access_token(55)
        with results_lock:
            results.append(token)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert call_count == 1
    assert results == ["ghs_concurrent_once"] * 8


def test_token_freshness_comparison_is_tz_aware() -> None:
    cached = InstallationAccessToken(
        token="ghs_tz",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    now = datetime.now(UTC)
    assert cached.expires_at.tzinfo is not None
    assert now.tzinfo is not None
    assert github_app_auth._token_is_fresh(cached, now=now) is True

    nearly_expired = InstallationAccessToken(
        token="ghs_tz",
        expires_at=now + timedelta(seconds=60),
    )
    assert github_app_auth._token_is_fresh(nearly_expired, now=now) is False


def test_default_http_client_lifecycle_closes_without_resource_warning() -> None:
    close_default_http_client()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        client = github_app_auth._get_default_http_client()
        assert client.is_closed is False
        close_default_http_client()
        assert client.is_closed is True

    resource_warnings = [w for w in caught if issubclass(w.category, ResourceWarning)]
    assert resource_warnings == []


# --- Step 3: OAuth user-token helpers ---


def test_exchange_oauth_code_returns_access_token_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "github_app_client_id", "Iv1.client")
    monkeypatch.setattr(settings, "github_app_client_secret", "client-secret")

    client = mock.MagicMock(spec=httpx.Client)
    response = mock.MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.json.return_value = {
        "access_token": "ghu_user_access_token_abc",
        "refresh_token": "ghr_must_never_be_returned",
        "token_type": "bearer",
    }
    client.post.return_value = response

    token = exchange_oauth_code_for_user_token("oauth-code", http_client=client)

    assert token == "ghu_user_access_token_abc"
    assert "ghr_must_never_be_returned" not in token
    client.post.assert_called_once()
    call = client.post.call_args
    assert call.args[0] == "https://github.com/login/oauth/access_token"
    assert call.kwargs["headers"]["Accept"] == "application/json"
    assert call.kwargs["data"]["client_id"] == "Iv1.client"
    assert call.kwargs["data"]["client_secret"] == "client-secret"
    assert call.kwargs["data"]["code"] == "oauth-code"


def test_exchange_oauth_code_200_with_error_body_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "github_app_client_id", "Iv1.client")
    monkeypatch.setattr(settings, "github_app_client_secret", "client-secret")
    client = mock.MagicMock(spec=httpx.Client)
    response = mock.MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.json.return_value = {
        "error": "bad_verification_code",
        "error_description": "The code passed is incorrect or expired.",
    }
    client.post.return_value = response

    with pytest.raises(GitHubAppAuthError, match="bad_verification_code"):
        exchange_oauth_code_for_user_token("bad-code", http_client=client)


def test_exchange_oauth_code_non_2xx_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "github_app_client_id", "Iv1.client")
    monkeypatch.setattr(settings, "github_app_client_secret", "client-secret")
    client = mock.MagicMock(spec=httpx.Client)
    response = mock.MagicMock(spec=httpx.Response)
    response.status_code = 500
    client.post.return_value = response

    with pytest.raises(GitHubAppAuthError, match="HTTP 500"):
        exchange_oauth_code_for_user_token("code", http_client=client)


def test_exchange_oauth_code_missing_client_config_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "github_app_client_id", None)
    monkeypatch.setattr(settings, "github_app_client_secret", "secret")
    with pytest.raises(GitHubAppConfigError, match="ARGUSS_GITHUB_APP_CLIENT_ID"):
        exchange_oauth_code_for_user_token("code", http_client=mock.MagicMock(spec=httpx.Client))

    monkeypatch.setattr(settings, "github_app_client_id", "Iv1.client")
    monkeypatch.setattr(settings, "github_app_client_secret", None)
    with pytest.raises(GitHubAppConfigError, match="ARGUSS_GITHUB_APP_CLIENT_SECRET"):
        exchange_oauth_code_for_user_token("code", http_client=mock.MagicMock(spec=httpx.Client))


def test_exchange_oauth_code_refresh_token_not_logged(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(settings, "github_app_client_id", "Iv1.client")
    monkeypatch.setattr(settings, "github_app_client_secret", "client-secret")
    refresh = "ghr_refresh_secret_must_not_appear"
    access = "ghu_access_secret_ok_to_return_only"
    client = mock.MagicMock(spec=httpx.Client)
    response = mock.MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.json.return_value = {
        "access_token": access,
        "refresh_token": refresh,
    }
    client.post.return_value = response

    with caplog.at_level("DEBUG"):
        token = exchange_oauth_code_for_user_token("code", http_client=client)

    assert token == access
    joined = " ".join(r.message for r in caplog.records)
    assert refresh not in joined
    assert access not in joined


def test_user_can_access_installation_true_for_present_id() -> None:
    client = mock.MagicMock(spec=httpx.Client)
    response = mock.MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.headers = {}
    response.json.return_value = {
        "total_count": 2,
        "installations": [{"id": 111}, {"id": 424242}],
    }
    client.get.return_value = response

    assert user_can_access_installation("ghu_user", 424242, http_client=client) is True
    call = client.get.call_args
    assert call.args[0] == "https://api.github.com/user/installations"
    assert call.kwargs["headers"]["Authorization"] == "Bearer ghu_user"
    assert call.kwargs["headers"]["Accept"] == "application/vnd.github+json"
    assert call.kwargs["headers"]["X-GitHub-Api-Version"] == "2022-11-28"


def test_user_can_access_installation_false_when_absent() -> None:
    client = mock.MagicMock(spec=httpx.Client)
    response = mock.MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.headers = {}
    response.json.return_value = {
        "total_count": 1,
        "installations": [{"id": 111}],
    }
    client.get.return_value = response

    assert user_can_access_installation("ghu_user", 424242, http_client=client) is False


def test_user_can_access_installation_compares_int_ids() -> None:
    client = mock.MagicMock(spec=httpx.Client)
    response = mock.MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.headers = {}
    response.json.return_value = {"installations": [{"id": 99}]}
    client.get.return_value = response

    assert user_can_access_installation("ghu_user", 99, http_client=client) is True
    assert isinstance(response.json.return_value["installations"][0]["id"], int)


def test_user_can_access_installation_follows_pagination() -> None:
    client = mock.MagicMock(spec=httpx.Client)
    page1 = mock.MagicMock(spec=httpx.Response)
    page1.status_code = 200
    page1.headers = {
        "Link": '<https://api.github.com/user/installations?page=2>; rel="next"',
    }
    page1.json.return_value = {"installations": [{"id": 1}]}
    page2 = mock.MagicMock(spec=httpx.Response)
    page2.status_code = 200
    page2.headers = {}
    page2.json.return_value = {"installations": [{"id": 777}]}
    client.get.side_effect = [page1, page2]

    assert user_can_access_installation("ghu_user", 777, http_client=client) is True
    assert client.get.call_count == 2
