"""Scan-frequency limits: per-IP hourly + per-wizard-session (in-memory)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.settings import settings as live_settings
from arguss.web.scan_inputs import save_scan_inputs
from arguss.web.scan_rate_limit import (
    IP_WINDOW_SECONDS,
    _ScanRateLimitState,
    check_scan_rate_limit,
)
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict
from tests.web.session_helpers import make_session_client, seed_github_installation

_HASH = "rate-limit-hash"


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    return make_session_client(monkeypatch)


def _tiny_invalid_upload(client: TestClient, fly_ip: str) -> Any:
    """Cheap scan trigger: passes the limiter, then fails lockfile parsing."""
    return client.post(
        "/dashboard/upload",
        files={"lockfile": ("package-lock.json", b"not json", "application/json")},
        headers={"Fly-Client-IP": fly_ip},
    )


# --- limiter state (unit) ---


def test_ip_budget_allows_under_and_denies_at_limit() -> None:
    state = _ScanRateLimitState()
    for _ in range(3):
        assert (
            state.check_and_count(ip="1.1.1.1", session_token=None, ip_limit=3, session_limit=10)
            is None
        )
    denial = state.check_and_count(ip="1.1.1.1", session_token=None, ip_limit=3, session_limit=10)
    assert denial is not None
    assert denial.scope == "ip"
    assert 1 <= denial.retry_after_seconds <= IP_WINDOW_SECONDS + 1


def test_ip_window_slides() -> None:
    state = _ScanRateLimitState()
    assert (
        state.check_and_count(
            ip="1.1.1.1", session_token=None, ip_limit=1, session_limit=10, now=100.0
        )
        is None
    )
    denied = state.check_and_count(
        ip="1.1.1.1", session_token=None, ip_limit=1, session_limit=10, now=200.0
    )
    assert denied is not None
    allowed_later = state.check_and_count(
        ip="1.1.1.1",
        session_token=None,
        ip_limit=1,
        session_limit=10,
        now=100.0 + IP_WINDOW_SECONDS + 1,
    )
    assert allowed_later is None


def test_two_ips_have_independent_budgets() -> None:
    state = _ScanRateLimitState()
    assert (
        state.check_and_count(ip="1.1.1.1", session_token=None, ip_limit=1, session_limit=10)
        is None
    )
    assert (
        state.check_and_count(ip="1.1.1.1", session_token=None, ip_limit=1, session_limit=10)
        is not None
    )
    # The other IP is unaffected.
    assert (
        state.check_and_count(ip="2.2.2.2", session_token=None, ip_limit=1, session_limit=10)
        is None
    )


def test_session_budget_enforced_alongside_ip() -> None:
    state = _ScanRateLimitState()
    for _ in range(2):
        assert (
            state.check_and_count(
                ip="1.1.1.1", session_token="wiz-1", ip_limit=100, session_limit=2
            )
            is None
        )
    denial = state.check_and_count(
        ip="1.1.1.1", session_token="wiz-1", ip_limit=100, session_limit=2
    )
    assert denial is not None
    assert denial.scope == "session"
    # A different session from the same IP still has budget.
    assert (
        state.check_and_count(ip="1.1.1.1", session_token="wiz-2", ip_limit=100, session_limit=2)
        is None
    )


def test_denied_request_consumes_no_budget() -> None:
    state = _ScanRateLimitState()
    assert (
        state.check_and_count(ip="1.1.1.1", session_token="wiz-1", ip_limit=100, session_limit=0)
        is not None
    )
    # The session denial must not have consumed IP budget.
    assert (
        state.check_and_count(ip="1.1.1.1", session_token=None, ip_limit=1, session_limit=0) is None
    )


# --- JSON API behavior ---


def test_scan_url_returns_429_with_retry_after_at_limit(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_scans_per_ip_per_hour", 0)
    response = client.post(
        "/scan/url",
        json={"url": "https://github.com/expressjs/express"},
    )
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "Retry-After" in response.headers
    assert "Scan rate limit" in response.json()["detail"]


def test_scan_upload_returns_429_at_limit(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_scans_per_ip_per_hour", 0)
    response = client.post(
        "/scan/upload",
        files={"lockfile": ("package-lock.json", b"{}", "application/json")},
    )
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "Retry-After" in response.headers


def test_scan_with_action_and_start_return_429_at_limit(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_scans_per_ip_per_hour", 0)
    body = {"url": "https://github.com/expressjs/express", "installation_id": 123}
    for path in ("/scan/with-action", "/scan/with-action/start"):
        response = client.post(path, json=body)
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS, path
        assert "Retry-After" in response.headers, path


# --- browser/HTMX behavior ---


def test_dashboard_scan_under_limit_proceeds_and_at_limit_gets_error_card(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_scans_per_ip_per_hour", 2)

    first = _tiny_invalid_upload(client, "203.0.113.5")
    second = _tiny_invalid_upload(client, "203.0.113.5")
    third = _tiny_invalid_upload(client, "203.0.113.5")

    # Under the limit the requests pass the limiter (they fail later on the
    # bogus lockfile, which is NOT a rate-limit rejection).
    assert first.status_code == status.HTTP_200_OK
    assert "Scan limit reached" not in first.text
    assert second.status_code == status.HTTP_200_OK
    # At the limit: 429 with the legible error card.
    assert third.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "Scan limit reached" in third.text
    assert "Retry-After" in third.headers


def test_dashboard_two_ips_independent(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_scans_per_ip_per_hour", 1)

    assert _tiny_invalid_upload(client, "203.0.113.5").status_code == status.HTTP_200_OK
    assert (
        _tiny_invalid_upload(client, "203.0.113.5").status_code == status.HTTP_429_TOO_MANY_REQUESTS
    )
    # A different client IP still has its own budget.
    assert _tiny_invalid_upload(client, "198.51.100.9").status_code == status.HTTP_200_OK


def test_kill_switch_disables_scan_limits(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_enabled", False)
    monkeypatch.setattr(live_settings, "rate_limit_scans_per_ip_per_hour", 0)
    monkeypatch.setattr(live_settings, "rate_limit_scans_per_session", 0)

    response = _tiny_invalid_upload(client, "203.0.113.5")
    assert response.status_code == status.HTTP_200_OK
    assert "Scan limit reached" not in response.text


def test_sse_stream_gets_are_not_limited(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_scans_per_ip_per_hour", 0)
    for path in (
        "/scan/with-action/stream/unknown-scan-id",
        "/dashboard/scan-with-action/stream/unknown-scan-id",
    ):
        response = client.get(path)
        assert response.status_code == status.HTTP_200_OK, path
        assert "scan_failed" in response.text, path


# --- wizard session limit on POST /authorize ---


def _wizard_authorize(client: TestClient) -> Any:
    scan = _cached_scan_dict(
        entries=[_cached_entry(package="left-pad", tier="auto_merge")],
        mode="A",
    )
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan),
        mock.patch.object(
            dashboard_mod,
            "register_scan_stream",
            new=mock.AsyncMock(return_value=("scan-rl-1", mock.MagicMock())),
        ),
        mock.patch.object(dashboard_mod, "run_scan_background", new=mock.AsyncMock()),
        mock.patch.object(dashboard_mod, "attach_background_task", new=mock.AsyncMock()),
    ):
        client.post(f"/assessment/{_HASH}/plan", follow_redirects=False)
        client.post(
            "/select",
            data={"selected_candidate_ids": ["cand-left-pad-001"]},
            follow_redirects=False,
        )
        seed_github_installation(client, 12345)
        return client.post("/authorize", follow_redirects=False)


def test_wizard_authorize_proceeds_under_session_limit(
    client: TestClient,
    wizard_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_scans_per_session", 10)
    response = _wizard_authorize(client)
    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"].startswith("/process")


def test_wizard_authorize_rejected_at_session_limit(
    client: TestClient,
    wizard_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_scans_per_session", 0)
    monkeypatch.setattr(live_settings, "rate_limit_scans_per_ip_per_hour", 100)
    response = _wizard_authorize(client)
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "Scan limit reached" in response.text


# --- assessment permalink: cache hit free, cache-miss rescan counted ---


def _scan_dict() -> dict[str, Any]:
    return _cached_scan_dict(entries=[_cached_entry(package="left-pad")], mode="A")


def test_assessment_cache_hit_is_not_counted(
    client: TestClient,
    wizard_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Limit 0 would reject ANY counted scan — a cache hit must still render.
    monkeypatch.setattr(live_settings, "rate_limit_scans_per_ip_per_hour", 0)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=_scan_dict()):
        response = client.get(f"/assessment/{_HASH}")
    assert response.status_code == status.HTTP_200_OK
    assert "Scan limit reached" not in response.text


def test_assessment_cache_miss_rescan_is_counted_and_limited(
    client: TestClient,
    wizard_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_scans_per_ip_per_hour", 0)
    save_scan_inputs(_HASH, "A", "https://github.com/expressjs/express", "HEAD", wizard_db)
    rescan = mock.AsyncMock(return_value=_scan_dict())
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=None),
        mock.patch.object(dashboard_mod, "_rescan_from_inputs", new=rescan),
    ):
        response = client.get(f"/assessment/{_HASH}")
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "Scan limit reached" in response.text
    rescan.assert_not_called()


def test_assessment_cache_miss_rescan_proceeds_under_limit(
    client: TestClient,
    wizard_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_scans_per_ip_per_hour", 5)
    save_scan_inputs(_HASH, "A", "https://github.com/expressjs/express", "HEAD", wizard_db)
    rescan = mock.AsyncMock(return_value=_scan_dict())
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=None),
        mock.patch.object(dashboard_mod, "_rescan_from_inputs", new=rescan),
    ):
        response = client.get(f"/assessment/{_HASH}")
    assert response.status_code == status.HTTP_200_OK
    rescan.assert_awaited_once()


# --- Anthropic ceiling regression (Step 2 unchanged) ---


def test_anthropic_ceiling_unaffected_by_scan_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import arguss.explanations._client as client_mod
    from arguss.explanations._budget import anthropic_calls_today
    from arguss.explanations._client import call_claude

    db = tmp_path / "budget.db"
    monkeypatch.setattr(live_settings, "db_path", db)
    monkeypatch.setattr(live_settings, "anthropic_api_key", "sk-ant-test-key")
    monkeypatch.setattr(live_settings, "anthropic_daily_ceiling", 5)
    # Scan limits at zero must not affect Claude calls.
    monkeypatch.setattr(live_settings, "rate_limit_scans_per_ip_per_hour", 0)
    monkeypatch.setattr(live_settings, "rate_limit_scans_per_session", 0)

    mock_client = mock.MagicMock()
    block = mock.MagicMock()
    block.text = "Still works."
    message = mock.MagicMock()
    message.content = [block]
    mock_client.messages.create.return_value = message
    monkeypatch.setattr(client_mod, "Anthropic", lambda **kwargs: mock_client)

    assert call_claude("system", "user") == "Still works."
    assert anthropic_calls_today(db) == 1


def test_check_scan_rate_limit_uses_wizard_cookie_not_oauth_session() -> None:
    """The session key is arguss_wizard_session; arguss_session is OAuth-only."""
    import inspect

    from arguss.web import scan_rate_limit as srl

    source = inspect.getsource(srl.check_scan_rate_limit)
    assert "WIZARD_SESSION_COOKIE" in source
    assert check_scan_rate_limit is not None
