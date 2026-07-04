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
    CandidateState,
    action_run_to_dict,
    add_action_run_candidate,
    candidate_state_label,
    candidate_state_secondary_detail,
    create_action_run,
    load_action_run,
    merge_authorization_commit_message,
    merge_authorization_pr_line,
    merge_escalation_primary_detail,
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


def _make_run(
    db: Path,
    *,
    head_sha: str | None = "abc123",
    pr_number: int = 42,
    merge_authorization: str | None = "engine",
    engine_score: int | None = 95,
    veto_signals: tuple[str, ...] = (),
    state: CandidateState = "pr_opened",
    pr_authorization_appended: bool = False,
) -> tuple[str, str]:
    run = create_action_run("scan-hash", "C", db, scan_ref="main")
    cand = add_action_run_candidate(
        run.id,
        "cand-1",
        "left-pad",
        "1.3.0",
        "1.3.1",
        db,
        state=state,
        pr_number=pr_number,
        head_sha=head_sha,
        merge_authorization=merge_authorization,
        engine_score=engine_score,
        veto_signals=veto_signals,
        pr_authorization_appended=pr_authorization_appended,
    )
    return run.id, cand.id


def _install_client_mock(handler: Any) -> mock.MagicMock:
    mock_client = mock.MagicMock()

    def _dispatch(method: str, url: str, **kwargs: Any) -> httpx.Response:
        return handler(method, url, **kwargs)

    mock_client.request.side_effect = _dispatch
    mock_client.get.side_effect = lambda url, **kwargs: _dispatch("GET", url, **kwargs)
    mock_client.patch.side_effect = lambda url, **kwargs: _dispatch("PATCH", url, **kwargs)
    mock_client.put.side_effect = lambda url, **kwargs: _dispatch("PUT", url, **kwargs)
    mock_client.__enter__ = mock.Mock(return_value=mock_client)
    mock_client.__exit__ = mock.Mock(return_value=False)
    return mock_client


@pytest.mark.asyncio
async def test_green_path_includes_authorization_commit_message(
    db: Path,
    fast_settings: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, _ = _make_run(db)
    merge_calls: list[dict[str, Any]] = []
    commit_message = merge_authorization_commit_message("engine", engine_score=95, veto_signals=())

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        if method == "GET" and url.endswith("/pulls/42"):
            return _httpx_response(200, {"body": "Existing PR body"})
        if method == "GET" and "/check-runs" in url:
            return _httpx_response(
                200,
                {"check_runs": [{"status": "completed", "conclusion": "success"}]},
            )
        if method == "PATCH" and url.endswith("/pulls/42"):
            return _httpx_response(200, {"body": kwargs.get("json", {}).get("body")})
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
    assert loaded.candidates[0].pr_authorization_appended is True
    assert loaded.state == "completed"
    assert merge_calls == [{"sha": "abc123", "commit_message": commit_message}]


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
    assert loaded.candidates[0].state_detail == merge_escalation_primary_detail("no_checks")
    assert (
        candidate_state_secondary_detail("no_checks")
        == "No check runs were observed on the head commit within the grace period."
    )
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
    assert github_calls <= 2


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
    commit_message = merge_authorization_commit_message("engine", engine_score=95, veto_signals=())
    assert merge_calls == [{"sha": "resolved-sha", "commit_message": commit_message}]


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
    assert github_calls == 2


def test_spawn_action_merge_task_requires_running_loop(db: Path) -> None:
    with pytest.raises(RuntimeError, match="no running event loop"):
        merge_mod.spawn_action_merge_task("run-id", _OWNER, _REPO, _TEST_PAT, db)


def test_merge_commit_message_engine_and_human_override() -> None:
    engine = merge_authorization_commit_message("engine", engine_score=88, veto_signals=())
    assert engine == "Merged by Arguss under engine envelope (AUTO_MERGE, score 88)"
    human = merge_authorization_commit_message(
        "human_override",
        engine_score=50,
        veto_signals=("trust.unavailable", "fix_kind.major"),
    )
    assert human == (
        "Merge authorized by operator; engine verdict was REVIEW_REQUIRED "
        "(trust.unavailable, fix_kind.major)"
    )
    assert merge_authorization_pr_line(engine).startswith("Armed for auto-merge:")
    assert candidate_state_label("pr_only") == "PR opened, review manually"
    assert candidate_state_label("ci_running") == "ci running"


@pytest.mark.asyncio
async def test_human_override_merge_commit_message(
    db: Path,
    fast_settings: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, _ = _make_run(
        db,
        merge_authorization="human_override",
        engine_score=60,
        veto_signals=("pipeline.test_reality",),
    )
    merge_calls: list[dict[str, Any]] = []
    commit_message = merge_authorization_commit_message(
        "human_override",
        engine_score=60,
        veto_signals=("pipeline.test_reality",),
    )

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        if method == "GET" and url.endswith("/pulls/42"):
            return _httpx_response(200, {"body": ""})
        if method == "GET" and "/check-runs" in url:
            return _httpx_response(
                200,
                {"check_runs": [{"status": "completed", "conclusion": "success"}]},
            )
        if method == "PATCH" and url.endswith("/pulls/42"):
            return _httpx_response(200, {"body": kwargs.get("json", {}).get("body")})
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
    assert merge_calls == [{"sha": "abc123", "commit_message": commit_message}]


@pytest.mark.asyncio
async def test_pr_patch_issued_once_for_merge_selected(
    db: Path,
    fast_settings: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, _ = _make_run(db)
    patch_calls = 0

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        nonlocal patch_calls
        if method == "GET" and url.endswith("/pulls/42"):
            return _httpx_response(200, {"body": "body"})
        if method == "PATCH" and url.endswith("/pulls/42"):
            patch_calls += 1
            return _httpx_response(200, {"body": "patched"})
        if method == "GET" and "/check-runs" in url:
            return _httpx_response(
                200,
                {"check_runs": [{"status": "in_progress", "conclusion": None}]},
            )
        if method == "PUT" and url.endswith("/merge"):
            return _httpx_response(200, {"merged": True})
        return _httpx_response(404)

    monkeypatch.setattr(merge_mod.settings, "mode_c_ci_poll_interval_seconds", 0.05)
    monkeypatch.setattr(merge_mod.settings, "mode_c_merge_wait_cap_seconds", 0.2)
    monkeypatch.setattr(merge_mod.httpx, "Client", lambda **_k: _install_client_mock(handler))
    monkeypatch.setattr(merge_mod, "is_kill_switch_active", lambda: False)

    await merge_mod.run_action_merge_task(run_id, _OWNER, _REPO, _TEST_PAT, db)

    loaded = load_action_run(run_id, db)
    assert loaded is not None
    assert patch_calls == 1
    assert loaded.candidates[0].pr_authorization_appended is True


@pytest.mark.asyncio
async def test_pr_patch_not_called_for_pr_only(
    db: Path,
    fast_settings: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = create_action_run("scan-hash", "C", db, scan_ref="main")
    add_action_run_candidate(
        run.id,
        "cand-pr-only",
        "left-pad",
        "1.3.0",
        "1.3.1",
        db,
        state="pr_only",
        pr_number=42,
        head_sha="abc123",
        merge_authorization=None,
    )
    github_calls = 0

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        nonlocal github_calls
        github_calls += 1
        return _httpx_response(404)

    monkeypatch.setattr(merge_mod.httpx, "Client", lambda **_k: _install_client_mock(handler))
    monkeypatch.setattr(merge_mod, "is_kill_switch_active", lambda: False)

    await merge_mod.run_action_merge_task(run.id, _OWNER, _REPO, _TEST_PAT, db)

    loaded = load_action_run(run.id, db)
    assert loaded is not None
    assert loaded.state == "completed"
    assert github_calls == 0


@pytest.mark.asyncio
async def test_pr_patch_failure_does_not_block_merge(
    db: Path,
    fast_settings: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, _ = _make_run(db)
    merge_calls: list[dict[str, Any]] = []
    commit_message = merge_authorization_commit_message("engine", engine_score=95, veto_signals=())

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        if method == "GET" and url.endswith("/pulls/42"):
            return _httpx_response(500)
        if method == "GET" and "/check-runs" in url:
            return _httpx_response(
                200,
                {"check_runs": [{"status": "completed", "conclusion": "success"}]},
            )
        if method == "PATCH" and url.endswith("/pulls/42"):
            return _httpx_response(500)
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
    assert loaded.candidates[0].pr_authorization_appended is True
    assert merge_calls == [{"sha": "abc123", "commit_message": commit_message}]
