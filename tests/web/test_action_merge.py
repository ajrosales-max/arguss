"""Tests for Mode C wait-and-merge background task."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest import mock

import httpx
import pytest

import arguss.web.action_merge as merge_mod
from arguss.web.action_runs import (
    action_run_to_dict,
    add_action_run_candidate,
    create_action_run,
    load_action_run,
)

_TEST_PAT = "ghp_test_pat_for_unit_tests_only_not_real"
_OWNER = "o"
_REPO = "r"


def _httpx_response(status_code: int, json_body: Any | None = None) -> httpx.Response:
    request = httpx.Request("GET", "https://api.github.com/repos/o/r")
    if json_body is None:
        return httpx.Response(status_code, request=request)
    return httpx.Response(status_code, request=request, json=json_body)


def _assert_no_secrets(value: object) -> None:
    blob = json.dumps(value).lower()
    assert _TEST_PAT.lower() not in blob
    assert "bearer" not in blob


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / "merge.db"


@pytest.fixture
def fast_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(merge_mod.settings, "mode_c_ci_poll_interval_seconds", 0)
    monkeypatch.setattr(merge_mod.settings, "mode_c_ci_grace_period_seconds", 0)
    monkeypatch.setattr(merge_mod.settings, "mode_c_merge_wait_cap_seconds", 1)


def _make_run(db: Path, *, head_sha: str | None = "abc123", pr_number: int = 42) -> tuple[str, str]:
    run = create_action_run("scan-hash", "C", db, scan_ref="main")
    cand = add_action_run_candidate(
        run.id,
        "cand-1",
        "left-pad",
        "1.3.0",
        "1.3.1",
        db,
        pr_number=pr_number,
        head_sha=head_sha,
    )
    return run.id, cand.id


def _install_client_mock(handler: Any) -> mock.MagicMock:
    mock_client = mock.MagicMock()

    def _dispatch(method: str, url: str, **kwargs: Any) -> httpx.Response:
        return handler(method, url, **kwargs)

    mock_client.request.side_effect = _dispatch
    mock_client.get.side_effect = lambda url, **kwargs: _dispatch("GET", url, **kwargs)
    mock_client.put.side_effect = lambda url, **kwargs: _dispatch("PUT", url, **kwargs)
    mock_client.__enter__ = mock.Mock(return_value=mock_client)
    mock_client.__exit__ = mock.Mock(return_value=False)
    return mock_client


@pytest.mark.asyncio
async def test_green_path_merge(
    db: Path,
    fast_settings: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, _ = _make_run(db)
    merge_calls: list[dict[str, Any]] = []

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        if method == "GET" and "/check-runs" in url:
            return _httpx_response(
                200,
                {
                    "check_runs": [
                        {"status": "completed", "conclusion": "success"},
                    ]
                },
            )
        if method == "PUT" and url.endswith("/merge"):
            merge_calls.append(kwargs.get("json") or {})
            return _httpx_response(200, {"merged": True})
        return _httpx_response(404)

    monkeypatch.setattr(merge_mod.httpx, "Client", lambda **_k: _install_client_mock(handler))
    monkeypatch.setattr(merge_mod, "is_kill_switch_active", lambda: False)

    await merge_mod.run_action_merge_task(run_id, _OWNER, _REPO, _TEST_PAT, db)

    loaded = load_action_run(run_id, db)
    assert loaded is not None
    assert loaded.candidates[0].state == "merged"
    assert loaded.state == "completed"
    assert merge_calls == [{"sha": "abc123"}]


@pytest.mark.asyncio
async def test_ci_failed(
    db: Path,
    fast_settings: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, _ = _make_run(db)
    merge_calls = 0

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        nonlocal merge_calls
        if method == "GET" and "/check-runs" in url:
            return _httpx_response(
                200,
                {
                    "check_runs": [
                        {"status": "completed", "conclusion": "failure"},
                    ]
                },
            )
        if method == "PUT" and url.endswith("/merge"):
            merge_calls += 1
            return _httpx_response(200, {})
        return _httpx_response(404)

    monkeypatch.setattr(merge_mod.httpx, "Client", lambda **_k: _install_client_mock(handler))
    monkeypatch.setattr(merge_mod, "is_kill_switch_active", lambda: False)

    await merge_mod.run_action_merge_task(run_id, _OWNER, _REPO, _TEST_PAT, db)

    loaded = load_action_run(run_id, db)
    assert loaded is not None
    assert loaded.candidates[0].state == "ci_failed"
    assert merge_calls == 0


@pytest.mark.asyncio
async def test_no_checks_after_grace(
    db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, _ = _make_run(db)
    merge_calls = 0
    monkeypatch.setattr(merge_mod.settings, "mode_c_ci_poll_interval_seconds", 0)
    monkeypatch.setattr(merge_mod.settings, "mode_c_ci_grace_period_seconds", 0)
    monkeypatch.setattr(merge_mod.settings, "mode_c_merge_wait_cap_seconds", 5)

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        nonlocal merge_calls
        if method == "GET" and "/check-runs" in url:
            return _httpx_response(200, {"check_runs": []})
        if method == "PUT" and url.endswith("/merge"):
            merge_calls += 1
            return _httpx_response(200, {})
        return _httpx_response(404)

    monkeypatch.setattr(merge_mod.httpx, "Client", lambda **_k: _install_client_mock(handler))
    monkeypatch.setattr(merge_mod, "is_kill_switch_active", lambda: False)

    await merge_mod.run_action_merge_task(run_id, _OWNER, _REPO, _TEST_PAT, db)

    loaded = load_action_run(run_id, db)
    assert loaded is not None
    assert loaded.candidates[0].state == "no_checks"
    assert merge_calls == 0


@pytest.mark.asyncio
async def test_sha_conflict_no_second_merge(
    db: Path,
    fast_settings: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, _ = _make_run(db)
    merge_calls = 0

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        nonlocal merge_calls
        if method == "GET" and "/check-runs" in url:
            return _httpx_response(
                200,
                {"check_runs": [{"status": "completed", "conclusion": "success"}]},
            )
        if method == "PUT" and url.endswith("/merge"):
            merge_calls += 1
            return _httpx_response(409, {"message": "Head branch was modified"})
        return _httpx_response(404)

    monkeypatch.setattr(merge_mod.httpx, "Client", lambda **_k: _install_client_mock(handler))
    monkeypatch.setattr(merge_mod, "is_kill_switch_active", lambda: False)

    await merge_mod.run_action_merge_task(run_id, _OWNER, _REPO, _TEST_PAT, db)

    loaded = load_action_run(run_id, db)
    assert loaded is not None
    assert loaded.candidates[0].state == "sha_conflict"
    assert merge_calls == 1


@pytest.mark.asyncio
async def test_timed_out(
    db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, _ = _make_run(db)
    merge_calls = 0
    monkeypatch.setattr(merge_mod.settings, "mode_c_ci_poll_interval_seconds", 0)
    monkeypatch.setattr(merge_mod.settings, "mode_c_ci_grace_period_seconds", 60)
    monkeypatch.setattr(merge_mod.settings, "mode_c_merge_wait_cap_seconds", 0)

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        nonlocal merge_calls
        if method == "GET" and "/check-runs" in url:
            return _httpx_response(
                200,
                {"check_runs": [{"status": "in_progress", "conclusion": None}]},
            )
        if method == "PUT" and url.endswith("/merge"):
            merge_calls += 1
            return _httpx_response(200, {})
        return _httpx_response(404)

    monkeypatch.setattr(merge_mod.httpx, "Client", lambda **_k: _install_client_mock(handler))
    monkeypatch.setattr(merge_mod, "is_kill_switch_active", lambda: False)

    await merge_mod.run_action_merge_task(run_id, _OWNER, _REPO, _TEST_PAT, db)

    loaded = load_action_run(run_id, db)
    assert loaded is not None
    assert loaded.candidates[0].state == "timed_out"
    assert merge_calls == 0


@pytest.mark.asyncio
async def test_kill_switch_mid_run(
    db: Path,
    fast_settings: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, _ = _make_run(db)
    github_calls = 0
    kill_active = False

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        nonlocal github_calls
        github_calls += 1
        if method == "GET" and "/check-runs" in url:
            return _httpx_response(
                200,
                {"check_runs": [{"status": "in_progress", "conclusion": None}]},
            )
        return _httpx_response(404)

    def kill_switch() -> bool:
        return kill_active

    async def run_task() -> None:
        nonlocal kill_active
        task = asyncio.create_task(
            merge_mod.run_action_merge_task(run_id, _OWNER, _REPO, _TEST_PAT, db)
        )
        await asyncio.sleep(0)
        kill_active = True
        await task

    monkeypatch.setattr(merge_mod.httpx, "Client", lambda **_k: _install_client_mock(handler))
    monkeypatch.setattr(merge_mod, "is_kill_switch_active", kill_switch)

    await run_task()

    loaded = load_action_run(run_id, db)
    assert loaded is not None
    assert loaded.candidates[0].state == "killed"
    assert github_calls <= 1


def test_registry_rows_no_token(db: Path) -> None:
    run = create_action_run("scan-hash", "C", db)
    add_action_run_candidate(run.id, "c1", "pkg", "1", "2", db, pr_number=1, head_sha="sha")
    loaded = load_action_run(run.id, db)
    assert loaded is not None
    _assert_no_secrets(action_run_to_dict(loaded))


@pytest.mark.asyncio
async def test_resume_head_sha_fetch(
    db: Path,
    fast_settings: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, _ = _make_run(db, head_sha=None)
    merge_calls: list[dict[str, Any]] = []

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        if method == "GET" and url.endswith("/pulls/42"):
            return _httpx_response(200, {"head": {"sha": "resolved-sha"}})
        if method == "GET" and "/check-runs" in url:
            return _httpx_response(
                200,
                {"check_runs": [{"status": "completed", "conclusion": "success"}]},
            )
        if method == "PUT" and url.endswith("/merge"):
            merge_calls.append(kwargs.get("json") or {})
            return _httpx_response(200, {"merged": True})
        return _httpx_response(404)

    monkeypatch.setattr(merge_mod.httpx, "Client", lambda **_k: _install_client_mock(handler))
    monkeypatch.setattr(merge_mod, "is_kill_switch_active", lambda: False)

    await merge_mod.run_action_merge_task(run_id, _OWNER, _REPO, _TEST_PAT, db)

    loaded = load_action_run(run_id, db)
    assert loaded is not None
    assert loaded.candidates[0].state == "merged"
    assert loaded.candidates[0].head_sha == "resolved-sha"
    assert merge_calls == [{"sha": "resolved-sha"}]


@pytest.mark.asyncio
async def test_null_head_sha_escalation(
    db: Path,
    fast_settings: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, _ = _make_run(db, head_sha=None)
    github_calls = 0

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        nonlocal github_calls
        github_calls += 1
        if method == "GET" and url.endswith("/pulls/42"):
            return _httpx_response(404)
        return _httpx_response(404)

    monkeypatch.setattr(merge_mod.httpx, "Client", lambda **_k: _install_client_mock(handler))
    monkeypatch.setattr(merge_mod, "is_kill_switch_active", lambda: False)

    await merge_mod.run_action_merge_task(run_id, _OWNER, _REPO, _TEST_PAT, db)

    loaded = load_action_run(run_id, db)
    assert loaded is not None
    assert loaded.candidates[0].state == "head_sha_unresolved"
    assert github_calls == 1


def test_spawn_action_merge_task_requires_running_loop(db: Path) -> None:
    with pytest.raises(RuntimeError, match="no running event loop"):
        merge_mod.spawn_action_merge_task("run-id", _OWNER, _REPO, _TEST_PAT, db)
