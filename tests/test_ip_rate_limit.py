"""General per-IP per-minute request-rate backstop (in-memory)."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from arguss.api import create_app
from arguss.settings import settings as live_settings
from arguss.web.ip_rate_limit import (
    IP_WINDOW_SECONDS,
    _IpRateLimitState,
    is_ip_rate_limit_exempt,
)
from tests.web.session_helpers import make_session_client


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    return make_session_client(monkeypatch)


# --- unit: state + exemptions ---


def test_under_limit_allows_at_limit_denies() -> None:
    state = _IpRateLimitState()
    for _ in range(3):
        assert state.check_and_count(ip="1.1.1.1", limit=3) is None
    denial = state.check_and_count(ip="1.1.1.1", limit=3)
    assert denial is not None
    assert 1 <= denial.retry_after_seconds <= IP_WINDOW_SECONDS + 1


def test_sliding_window_releases_budget() -> None:
    state = _IpRateLimitState()
    assert state.check_and_count(ip="1.1.1.1", limit=1, now=100.0) is None
    assert state.check_and_count(ip="1.1.1.1", limit=1, now=150.0) is not None
    assert state.check_and_count(ip="1.1.1.1", limit=1, now=100.0 + IP_WINDOW_SECONDS + 1) is None


def test_prune_keeps_structure_bounded() -> None:
    state = _IpRateLimitState()
    for i in range(50):
        assert state.check_and_count(ip=f"10.0.0.{i}", limit=1, now=0.0) is None
    assert state.tracked_ip_count() == 50
    # Advance past the window and touch one IP — prune drops the rest.
    assert state.check_and_count(ip="10.0.0.0", limit=1, now=IP_WINDOW_SECONDS + 1) is None
    assert state.tracked_ip_count() <= 1


def test_two_ips_independent_budgets() -> None:
    state = _IpRateLimitState()
    assert state.check_and_count(ip="1.1.1.1", limit=1) is None
    assert state.check_and_count(ip="1.1.1.1", limit=1) is not None
    assert state.check_and_count(ip="2.2.2.2", limit=1) is None


def test_exempt_paths() -> None:
    assert is_ip_rate_limit_exempt("/health")
    assert is_ip_rate_limit_exempt("/static/css/base.css")
    assert is_ip_rate_limit_exempt("/static/images/favicon.ico")
    assert is_ip_rate_limit_exempt("/github/callback")
    assert is_ip_rate_limit_exempt("/scan/with-action/stream/abc")
    assert is_ip_rate_limit_exempt("/dashboard/scan-with-action/stream/abc")
    assert not is_ip_rate_limit_exempt("/github/install")
    assert not is_ip_rate_limit_exempt("/scan")
    assert not is_ip_rate_limit_exempt("/why-arguss")


# --- HTTP integration ---


def test_exceeding_per_minute_cap_returns_429_with_retry_after(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_ip_per_minute", 2)
    headers = {"Fly-Client-IP": "203.0.113.10"}
    assert client.get("/why-arguss", headers=headers).status_code == status.HTTP_200_OK
    assert client.get("/why-arguss", headers=headers).status_code == status.HTTP_200_OK
    response = client.get("/why-arguss", headers=headers)
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "Retry-After" in response.headers
    assert "Too many requests" in response.text or "rate limit" in response.text.lower()


def test_json_api_gets_json_429(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_ip_per_minute", 0)
    response = client.post(
        "/scan/url",
        json={"url": "https://github.com/expressjs/express"},
        headers={"Fly-Client-IP": "203.0.113.11"},
    )
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "Retry-After" in response.headers
    body = response.json()
    assert "detail" in body
    assert "rate limit" in body["detail"].lower()


def test_health_never_limited(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_ip_per_minute", 0)
    headers = {"Fly-Client-IP": "203.0.113.12"}
    for _ in range(20):
        assert client.get("/health", headers=headers).status_code == status.HTTP_200_OK


def test_static_assets_not_counted(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_ip_per_minute", 1)
    headers = {"Fly-Client-IP": "203.0.113.13"}
    for _ in range(10):
        assert client.get("/static/css/base.css", headers=headers).status_code == status.HTTP_200_OK
    # Budget still available for a real page.
    assert client.get("/why-arguss", headers=headers).status_code == status.HTTP_200_OK
    assert (
        client.get("/why-arguss", headers=headers).status_code == status.HTTP_429_TOO_MANY_REQUESTS
    )


def test_sse_stream_get_not_counted(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_ip_per_minute", 1)
    headers = {"Fly-Client-IP": "203.0.113.14"}
    for path in (
        "/scan/with-action/stream/unknown-scan-id",
        "/dashboard/scan-with-action/stream/unknown-scan-id",
    ):
        for _ in range(5):
            assert client.get(path, headers=headers).status_code == status.HTTP_200_OK
    assert client.get("/why-arguss", headers=headers).status_code == status.HTTP_200_OK
    assert (
        client.get("/why-arguss", headers=headers).status_code == status.HTTP_429_TOO_MANY_REQUESTS
    )


def test_github_callback_excluded_install_may_be_limited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_ip_per_minute", 0)
    monkeypatch.setattr(live_settings, "session_secret", "unit-test-session-secret")
    monkeypatch.setattr(live_settings, "require_auth", False)
    monkeypatch.setattr(live_settings, "demo_password", None)
    client = TestClient(create_app())
    headers = {"Fly-Client-IP": "203.0.113.15"}

    callback = client.get("/github/callback", headers=headers, follow_redirects=False)
    assert callback.status_code != status.HTTP_429_TOO_MANY_REQUESTS

    install = client.get("/github/install", headers=headers, follow_redirects=False)
    assert install.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "Retry-After" in install.headers


def test_two_ips_independent_at_http(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_ip_per_minute", 1)
    a = {"Fly-Client-IP": "203.0.113.20"}
    b = {"Fly-Client-IP": "203.0.113.21"}
    assert client.get("/why-arguss", headers=a).status_code == status.HTTP_200_OK
    assert client.get("/why-arguss", headers=a).status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert client.get("/why-arguss", headers=b).status_code == status.HTTP_200_OK


def test_kill_switch_disables_backstop(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_enabled", False)
    monkeypatch.setattr(live_settings, "rate_limit_ip_per_minute", 0)
    headers = {"Fly-Client-IP": "203.0.113.22"}
    for _ in range(5):
        assert client.get("/why-arguss", headers=headers).status_code == status.HTTP_200_OK


def test_kill_switch_also_disables_scan_and_anthropic_layers(
    client: TestClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One switch turns off the backstop, scan limits, and Anthropic ceiling."""
    monkeypatch.setattr(live_settings, "rate_limit_enabled", False)
    monkeypatch.setattr(live_settings, "rate_limit_ip_per_minute", 0)
    monkeypatch.setattr(live_settings, "rate_limit_scans_per_ip_per_hour", 0)
    monkeypatch.setattr(live_settings, "rate_limit_scans_per_session", 0)
    monkeypatch.setattr(live_settings, "anthropic_daily_ceiling", 0)
    monkeypatch.setattr(live_settings, "anthropic_api_key", "sk-ant-test-key")
    monkeypatch.setattr(live_settings, "db_path", tmp_path / "budget.db")

    headers = {"Fly-Client-IP": "203.0.113.23"}
    # Backstop + scan limits off: a scan upload attempt passes the limiters
    # (then fails on bogus lockfile content — not a 429).
    upload = client.post(
        "/dashboard/upload",
        files={"lockfile": ("package-lock.json", b"not json", "application/json")},
        headers=headers,
    )
    assert upload.status_code == status.HTTP_200_OK
    assert "rate limit" not in upload.text.lower()
    assert "Scan limit reached" not in upload.text

    import arguss.explanations._client as client_mod
    from arguss.explanations._client import call_claude

    mock_client = mock.MagicMock()
    block = mock.MagicMock()
    block.text = "ok"
    message = mock.MagicMock()
    message.content = [block]
    mock_client.messages.create.return_value = message
    monkeypatch.setattr(client_mod, "Anthropic", lambda **kwargs: mock_client)

    assert call_claude("system", "user") == "ok"
    mock_client.messages.create.assert_called_once()


def test_scan_limits_still_enforce_under_backstop(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Under the per-minute backstop, Step 3 scan limits still apply (separate layer)."""
    monkeypatch.setattr(live_settings, "rate_limit_ip_per_minute", 100)
    monkeypatch.setattr(live_settings, "rate_limit_scans_per_ip_per_hour", 0)
    headers = {"Fly-Client-IP": "203.0.113.24"}
    response = client.post(
        "/dashboard/upload",
        files={"lockfile": ("package-lock.json", b"not json", "application/json")},
        headers=headers,
    )
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "Scan limit reached" in response.text
