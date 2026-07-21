"""Global daily Anthropic call ceiling (durable, atomic, fail-soft)."""

from __future__ import annotations

import threading
from pathlib import Path
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.explanations._client as client_mod
from arguss.api import create_app
from arguss.core.cache import get_connection
from arguss.core.serialization import attach_executive_summary
from arguss.explanations._budget import anthropic_calls_today, try_reserve_anthropic_call
from arguss.explanations._client import call_claude
from arguss.settings import settings as live_settings


@pytest.fixture
def budget_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db = tmp_path / "budget.db"
    monkeypatch.setattr(live_settings, "db_path", db)
    monkeypatch.setattr(live_settings, "anthropic_api_key", "sk-ant-test-key")
    monkeypatch.setattr(live_settings, "rate_limit_enabled", True)
    return db


def _mock_anthropic(
    monkeypatch: pytest.MonkeyPatch,
    *,
    text: str = "Claude prose.",
) -> mock.MagicMock:
    mock_client = mock.MagicMock()
    block = mock.MagicMock()
    block.text = text
    message = mock.MagicMock()
    message.content = [block]
    mock_client.messages.create.return_value = message
    monkeypatch.setattr(client_mod, "Anthropic", lambda **kwargs: mock_client)
    return mock_client


def _seed_calls(db: Path, count: int, *, ceiling: int = 10_000) -> None:
    for _ in range(count):
        assert try_reserve_anthropic_call(db, ceiling=ceiling)


# --- ceiling enforcement at call_claude ---


def test_under_ceiling_call_proceeds_and_counter_increments(
    budget_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "anthropic_daily_ceiling", 5)
    mock_client = _mock_anthropic(monkeypatch, text="Under the ceiling.")

    result = call_claude("system", "user")

    assert result == "Under the ceiling."
    mock_client.messages.create.assert_called_once()
    assert anthropic_calls_today(budget_db) == 1


def test_at_ceiling_returns_none_without_calling_api(
    budget_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "anthropic_daily_ceiling", 2)
    _seed_calls(budget_db, 2)
    mock_client = _mock_anthropic(monkeypatch)

    result = call_claude("system", "user")

    assert result is None
    mock_client.messages.create.assert_not_called()
    assert anthropic_calls_today(budget_db) == 2


def test_ceiling_of_zero_blocks_all_calls(budget_db: Path) -> None:
    assert try_reserve_anthropic_call(budget_db, ceiling=0) is False
    assert anthropic_calls_today(budget_db) == 0


# --- durability (load-bearing: an in-memory counter would fail this) ---


def test_counter_survives_a_fresh_connection(budget_db: Path) -> None:
    _seed_calls(budget_db, 3)

    # Simulate a restart: brand-new connection to the same file, no shared
    # in-process state with the reserve calls above.
    fresh = get_connection(budget_db)
    try:
        row = fresh.execute("SELECT calls FROM anthropic_daily_usage").fetchone()
    finally:
        fresh.close()
    assert row is not None
    assert row["calls"] == 3


def test_ceiling_still_enforced_after_restart(
    budget_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "anthropic_daily_ceiling", 3)
    _seed_calls(budget_db, 3)
    mock_client = _mock_anthropic(monkeypatch)

    # Nothing in memory carries over between call_claude invocations; the
    # count comes purely from the file, as it would after a deploy.
    assert call_claude("system", "user") is None
    mock_client.messages.create.assert_not_called()


# --- atomicity ---


def test_concurrent_reserves_do_not_exceed_ceiling(budget_db: Path) -> None:
    ceiling = 5
    _seed_calls(budget_db, ceiling - 1, ceiling=ceiling)

    barrier = threading.Barrier(2)
    results: list[bool] = []
    lock = threading.Lock()

    def racer() -> None:
        barrier.wait()
        outcome = try_reserve_anthropic_call(budget_db, ceiling=ceiling)
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=racer) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(results) == [False, True]
    assert anthropic_calls_today(budget_db) == ceiling


def test_concurrent_call_claude_makes_exactly_one_api_call_at_last_slot(
    budget_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ceiling = 4
    monkeypatch.setattr(live_settings, "anthropic_daily_ceiling", ceiling)
    _seed_calls(budget_db, ceiling - 1)
    mock_client = _mock_anthropic(monkeypatch)

    barrier = threading.Barrier(2)

    def racer() -> None:
        barrier.wait()
        call_claude("system", "user")

    threads = [threading.Thread(target=racer) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert mock_client.messages.create.call_count == 1
    assert anthropic_calls_today(budget_db) == ceiling


# --- kill switch ---


def test_kill_switch_disables_enforcement(
    budget_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "rate_limit_enabled", False)
    monkeypatch.setattr(live_settings, "anthropic_daily_ceiling", 1)
    _seed_calls(budget_db, 1)
    mock_client = _mock_anthropic(monkeypatch, text="Kill switch open.")

    result = call_claude("system", "user")

    assert result == "Kill switch open."
    mock_client.messages.create.assert_called_once()
    # Enforcement off means no reservation either: counter untouched.
    assert anthropic_calls_today(budget_db) == 1


# --- graceful degradation with the ceiling hit ---


def _scan_entry(*, finding_id: str = "finding-abc") -> dict:
    return {
        "finding": {
            "finding_id": finding_id,
            "advisory_id": "GHSA-ceiling-1",
            "title": "GHSA-ceiling-1: example issue",
            "description": "Example vulnerability description.",
            "cvss_score": 7.5,
            "dependency": {"name": "lodash", "version": "4.17.20"},
        },
        "candidate": {
            "package": "lodash",
            "from_version": "4.17.20",
            "to_version": "4.17.21",
            "fix_kind": "patch",
        },
        "verdict": {
            "tier": "review_required",
            "score": 55,
            "reasons": ["Patch within semver range"],
            "veto_signals": [],
        },
    }


def test_finding_explain_degrades_to_unavailable_when_ceiling_hit(
    budget_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "anthropic_daily_ceiling", 1)
    _seed_calls(budget_db, 1)
    mock_client = _mock_anthropic(monkeypatch)
    client = TestClient(create_app())

    scan = {"entries": [_scan_entry()]}
    with mock.patch(
        "arguss.explanations.scan_cache.get_cached_scan_response",
        return_value=scan,
    ):
        response = client.post(
            "/dashboard/finding-explain",
            data={"scan_hash": "ceilinghash", "finding_id": "finding-abc"},
        )

    assert response.status_code == status.HTTP_200_OK
    assert "No explanation available" in response.text
    mock_client.messages.create.assert_not_called()


def test_scan_payload_still_completes_with_ceiling_hit(
    budget_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exec-summary path scans go through omits Claude, never errors."""
    monkeypatch.setattr(live_settings, "anthropic_daily_ceiling", 1)
    _seed_calls(budget_db, 1)
    mock_client = _mock_anthropic(monkeypatch)

    payload = {
        "repo_path": "/tmp/repo",
        "lockfile_path": "/tmp/repo/package-lock.json",
        "entries": [],
        "skipped_findings": [],
        "summary": {"total_findings": 0, "total_candidates": 0},
    }
    enriched = attach_executive_summary(payload)

    assert enriched["executive_summary"] is None
    mock_client.messages.create.assert_not_called()
