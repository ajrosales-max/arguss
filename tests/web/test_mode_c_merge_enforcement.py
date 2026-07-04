"""Tests for Step 2 fresh-tier merge enforcement and pr_only registry rows."""

from __future__ import annotations

from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock

import pytest

import arguss.web.action_merge as merge_mod
import arguss.web.github_action as github_action_mod
import arguss.web.mode_c_workflow as mode_c_mod
from arguss.core.models import FixTier
from arguss.settings import settings
from arguss.web.action_runs import (
    DeclineMergeAuthorizationError,
    create_action_run,
    finalize_action_run_if_terminal,
    is_action_run_terminal,
    load_action_run,
    populate_action_run_candidates,
)
from arguss.web.github_action import ActionResult, PatPermissionResult
from tests.test_scan_with_action_endpoint import (
    _EXPRESS_URL,
    _TEST_PAT,
    _proposal_entry,
    _proposal_report,
)

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "lockfiles"


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "merge-enforcement.db"
    monkeypatch.setattr(settings, "db_path", path)
    return path


def _work_tree(tmp_path: Path) -> Path:
    lockfile = _FIXTURES / "minimal.json"
    (tmp_path / "package-lock.json").write_bytes(lockfile.read_bytes())
    return tmp_path


def _mergeable_actions(*actions: ActionResult) -> list[ActionResult]:
    return list(actions)


def test_effective_auto_merge_drops_forged_decline_tier() -> None:
    entry = _proposal_entry(tier=FixTier.DECLINE, package="declined-pkg")
    opened = ActionResult(
        candidate_id=entry.candidate.candidate_id,
        status="opened",
        pr_url="https://github.com/o/r/pull/1",
        pr_number=1,
        reason=None,
    )
    forged = frozenset({entry.candidate.candidate_id})
    effective = mode_c_mod._effective_auto_merge_candidate_ids(
        [entry],
        _mergeable_actions(opened),
        forged,
        selected_candidate_ids=[entry.candidate.candidate_id],
    )
    assert effective == frozenset()


def test_effective_auto_merge_drops_merge_without_pr_selection() -> None:
    entry_a = _proposal_entry(tier=FixTier.AUTO_MERGE, package="left-pad")
    entry_b = _proposal_entry(tier=FixTier.AUTO_MERGE, package="lodash")
    opened_a = ActionResult(
        candidate_id=entry_a.candidate.candidate_id,
        status="opened",
        pr_url="https://github.com/o/r/pull/1",
        pr_number=1,
        reason=None,
    )
    opened_b = ActionResult(
        candidate_id=entry_b.candidate.candidate_id,
        status="opened",
        pr_url="https://github.com/o/r/pull/2",
        pr_number=2,
        reason=None,
    )
    merge_both = frozenset({entry_a.candidate.candidate_id, entry_b.candidate.candidate_id})
    effective = mode_c_mod._effective_auto_merge_candidate_ids(
        [entry_a, entry_b],
        _mergeable_actions(opened_a, opened_b),
        merge_both,
        selected_candidate_ids=[entry_a.candidate.candidate_id],
    )
    assert effective == frozenset({entry_a.candidate.candidate_id})


def test_effective_auto_merge_drops_unknown_ids() -> None:
    entry = _proposal_entry(tier=FixTier.AUTO_MERGE, package="left-pad")
    opened = ActionResult(
        candidate_id=entry.candidate.candidate_id,
        status="opened",
        pr_url="https://github.com/o/r/pull/1",
        pr_number=1,
        reason=None,
    )
    effective = mode_c_mod._effective_auto_merge_candidate_ids(
        [entry],
        _mergeable_actions(opened),
        frozenset({entry.candidate.candidate_id, "unknown-candidate-id"}),
        selected_candidate_ids=[entry.candidate.candidate_id, "unknown-candidate-id"],
    )
    assert effective == frozenset({entry.candidate.candidate_id})


def test_populate_review_required_gets_human_override(db: Path) -> None:
    entry = _proposal_entry(tier=FixTier.REVIEW_REQUIRED, package="review-pkg")
    opened = ActionResult(
        candidate_id=entry.candidate.candidate_id,
        status="opened",
        pr_url="https://github.com/o/r/pull/1",
        pr_number=1,
        reason=None,
    )
    run = create_action_run("scan", "C", db)
    created = populate_action_run_candidates(
        run.id,
        [entry],
        [opened],
        db,
        auto_merge_candidate_ids={entry.candidate.candidate_id},
    )
    assert len(created) == 1
    assert created[0].state == "pr_opened"
    assert created[0].merge_authorization == "human_override"


def test_populate_uses_fresh_tier_not_cached_auto_merge(db: Path) -> None:
    entry = _proposal_entry(tier=FixTier.REVIEW_REQUIRED, package="stale-cache-pkg")
    opened = ActionResult(
        candidate_id=entry.candidate.candidate_id,
        status="opened",
        pr_url="https://github.com/o/r/pull/1",
        pr_number=1,
        reason=None,
    )
    run = create_action_run("scan", "C", db)
    created = populate_action_run_candidates(
        run.id,
        [entry],
        [opened],
        db,
        auto_merge_candidate_ids={entry.candidate.candidate_id},
    )
    assert created[0].merge_authorization == "human_override"
    loaded = load_action_run(run.id, db)
    assert loaded is not None
    assert loaded.candidates[0].merge_authorization == "human_override"


def test_populate_raises_on_decline_in_auto_merge_set(db: Path) -> None:
    entry = _proposal_entry(tier=FixTier.DECLINE, package="declined")
    opened = ActionResult(
        candidate_id=entry.candidate.candidate_id,
        status="opened",
        pr_url="https://github.com/o/r/pull/1",
        pr_number=1,
        reason=None,
    )
    run = create_action_run("scan", "C", db)
    with pytest.raises(DeclineMergeAuthorizationError):
        populate_action_run_candidates(
            run.id,
            [entry],
            [opened],
            db,
            auto_merge_candidate_ids={entry.candidate.candidate_id},
        )


@pytest.mark.asyncio
async def test_decline_with_forged_merge_id_becomes_pr_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    db: Path,
    allow_decline_override,
) -> None:
    allow_decline_override(True)
    work_tree = _work_tree(tmp_path)
    entry = _proposal_entry(tier=FixTier.DECLINE, package="declined-pkg")
    report = _proposal_report(work_tree, (entry,))
    opened = ActionResult(
        candidate_id=entry.candidate.candidate_id,
        status="opened",
        pr_url="https://github.com/o/r/pull/1",
        pr_number=1,
        reason=None,
    )
    spawn_mock = mock.MagicMock()
    monkeypatch.setattr(mode_c_mod, "spawn_action_merge_task", spawn_mock)
    monkeypatch.setattr(
        github_action_mod,
        "_check_pat_permissions_sync",
        lambda *_a, **_k: PatPermissionResult(sufficient=True, scopes_found=["push"]),
    )
    forged_merge = frozenset({entry.candidate.candidate_id})

    with (
        mock.patch.object(mode_c_mod, "shallow_clone", return_value=work_tree),
        mock.patch.object(mode_c_mod, "propose_fixes", return_value=report),
        mock.patch.object(
            mode_c_mod,
            "run_mode_c_actions",
            new_callable=AsyncMock,
            return_value=[opened],
        ),
    ):
        result = await mode_c_mod.execute_scan_with_action(
            url=_EXPRESS_URL,
            pat=_TEST_PAT,
            selected_candidate_ids=[entry.candidate.candidate_id],
            auto_merge_candidate_ids=forged_merge,
        )

    assert result.action_run_id is not None
    spawn_mock.assert_called_once()
    action_run = load_action_run(result.action_run_id, db)
    assert action_run is not None
    assert len(action_run.candidates) == 1
    assert action_run.candidates[0].state == "pr_only"
    assert action_run.candidates[0].merge_authorization is None


@pytest.mark.asyncio
async def test_pr_only_rows_skip_merge_task_api_calls(
    db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from arguss.web.action_runs import add_action_run_candidate

    monkeypatch.setattr(merge_mod.settings, "mode_c_ci_poll_interval_seconds", 0)
    monkeypatch.setattr(merge_mod.settings, "mode_c_ci_grace_period_seconds", 0)
    monkeypatch.setattr(merge_mod.settings, "mode_c_merge_wait_cap_seconds", 1)

    run = create_action_run("scan", "C", db)
    add_action_run_candidate(
        run.id,
        "cand-pr-only",
        "left-pad",
        "1.0.0",
        "1.0.1",
        db,
        state="pr_only",
        pr_number=42,
        head_sha="abc123",
        merge_authorization=None,
    )

    client_mock = mock.MagicMock()
    client_mock.__enter__ = mock.Mock(return_value=client_mock)
    client_mock.__exit__ = mock.Mock(return_value=False)
    monkeypatch.setattr(merge_mod.httpx, "Client", lambda **_k: client_mock)
    monkeypatch.setattr(merge_mod, "is_kill_switch_active", lambda: False)

    await merge_mod.run_action_merge_task(run.id, "o", "r", _TEST_PAT, db)

    client_mock.get.assert_not_called()
    client_mock.put.assert_not_called()
    loaded = load_action_run(run.id, db)
    assert loaded is not None
    assert loaded.candidates[0].state == "pr_only"
    assert loaded.state == "completed"


@pytest.mark.asyncio
async def test_all_pr_only_run_terminalizes_immediately(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    db: Path,
) -> None:
    work_tree = _work_tree(tmp_path)
    entry = _proposal_entry(tier=FixTier.AUTO_MERGE, package="left-pad")
    report = _proposal_report(work_tree, (entry,))
    opened = ActionResult(
        candidate_id=entry.candidate.candidate_id,
        status="opened",
        pr_url="https://github.com/o/r/pull/1",
        pr_number=1,
        reason=None,
        head_sha="abc123",
    )

    def _immediate_merge_task(run_id, *_args, **_kwargs) -> None:
        finalize_action_run_if_terminal(run_id, db)

    monkeypatch.setattr(
        github_action_mod,
        "_check_pat_permissions_sync",
        lambda *_a, **_k: PatPermissionResult(sufficient=True, scopes_found=["push"]),
    )
    monkeypatch.setattr(mode_c_mod, "spawn_action_merge_task", _immediate_merge_task)

    with (
        mock.patch.object(mode_c_mod, "shallow_clone", return_value=work_tree),
        mock.patch.object(mode_c_mod, "propose_fixes", return_value=report),
        mock.patch.object(
            mode_c_mod,
            "run_mode_c_actions",
            new_callable=AsyncMock,
            return_value=[opened],
        ),
    ):
        result = await mode_c_mod.execute_scan_with_action(
            url=_EXPRESS_URL,
            pat=_TEST_PAT,
            auto_merge_candidate_ids=frozenset(),
        )

    assert result.action_run_id is not None
    action_run = load_action_run(result.action_run_id, db)
    assert action_run is not None
    assert len(action_run.candidates) == 1
    assert action_run.candidates[0].state == "pr_only"
    assert is_action_run_terminal(action_run)
    assert action_run.state == "completed"
