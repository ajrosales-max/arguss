"""Tests for Mode C auto-merge opt-in and process hydration."""

from __future__ import annotations

from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
import arguss.web.github_action as github_action_mod
import arguss.web.mode_c_workflow as mode_c_mod
from arguss.api import app as api_app
from arguss.core.cache import get_connection, init_db
from arguss.core.models import FixTier
from arguss.settings import settings
from arguss.web.action_records import (
    PROutcome,
    create_action_record,
    load_action_record,
    update_pr_outcome,
)
from arguss.web.action_runs import create_action_run, load_action_run
from arguss.web.github_action import ActionResult, PatPermissionResult
from arguss.web.process_hydration import build_process_hydration
from arguss.web.wizard_session import load_session
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict
from tests.test_scan_with_action_endpoint import (
    _EXPRESS_URL,
    _TEST_PAT,
    _proposal_entry,
    _proposal_report,
)

_HASH = "auto-merge-select-demo"

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "lockfiles"


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "auto-merge.db"
    monkeypatch.setattr(settings, "db_path", path)
    return path


def _work_tree(tmp_path: Path) -> Path:
    lockfile = _FIXTURES / "minimal.json"
    (tmp_path / "package-lock.json").write_bytes(lockfile.read_bytes())
    return tmp_path


def test_migration_010_adds_auto_merge_candidate_ids(tmp_path: Path) -> None:
    conn = get_connection(tmp_path / "test.db")
    init_db(conn)

    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'action_records'"
    ).fetchone()
    assert row is not None

    columns = {
        r["name"]: r["type"] for r in conn.execute("PRAGMA table_info(action_records)").fetchall()
    }
    assert columns["action_id"] == "TEXT"
    assert columns["scan_hash"] == "TEXT"
    action_cols = {r["name"] for r in conn.execute("PRAGMA table_info(action_records)").fetchall()}
    assert "auto_merge_candidate_ids" in action_cols
    from arguss.web.wizard_session import ensure_table

    ensure_table(tmp_path / "wizard.db")
    wconn = get_connection(tmp_path / "wizard.db")
    wizard_cols = {
        r["name"] for r in wconn.execute("PRAGMA table_info(wizard_sessions)").fetchall()
    }
    assert "auto_merge_candidate_ids" in wizard_cols

    version_row = conn.execute("SELECT version FROM schema_version WHERE version = 10").fetchone()
    assert version_row is not None


def test_process_hydration_endpoint(client: TestClient, db: Path) -> None:
    record = create_action_record(
        scan_hash="abc123",
        repo_display="o/r",
        selected_candidate_ids=["cand-1"],
        db_path=db,
        auto_merge_candidate_ids=["cand-1"],
    )
    update_pr_outcome(
        record.action_id,
        PROutcome(
            candidate_id="cand-1",
            package="left-pad",
            from_version="1.0.0",
            to_version="1.0.1",
            fix_kind="patch",
            status="opened",
            pr_number=42,
            pr_url="https://github.com/o/r/pull/42",
        ),
        db,
    )
    action_run = create_action_run(
        record.scan_hash,
        "C",
        db,
        wizard_action_id=record.action_id,
    )

    response = client.get(f"/dashboard/wizard-process/{record.action_id}")

    assert response.status_code == 200
    payload = response.json()
    assert payload["has_record"] is True
    assert payload["tracks_auto_merge"] is True
    assert payload["auto_merge_candidate_ids"] == ["cand-1"]
    assert payload["action_run_id"] == action_run.id
    assert len(payload["pr_outcomes"]) == 1
    assert payload["pr_outcomes"][0]["package"] == "left-pad"

    expected = build_process_hydration(load_action_record(record.action_id, db), action_run)
    assert payload == expected


@pytest.mark.asyncio
async def test_empty_auto_merge_set_skips_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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
    )
    spawn_mock = mock.MagicMock()
    monkeypatch.setattr(mode_c_mod, "spawn_action_merge_task", spawn_mock)
    monkeypatch.setattr(
        github_action_mod,
        "_check_pat_permissions_sync",
        lambda *_a, **_k: PatPermissionResult(sufficient=True, scopes_found=["push"]),
    )

    with (
        mock.patch.object(mode_c_mod, "shallow_clone", return_value=work_tree),
        mock.patch.object(mode_c_mod, "propose_fixes", return_value=report),
        mock.patch.object(
            mode_c_mod, "run_mode_c_actions", new_callable=AsyncMock, return_value=[opened]
        ),
    ):
        result = await mode_c_mod.execute_scan_with_action(
            url=_EXPRESS_URL,
            pat=_TEST_PAT,
            auto_merge_candidate_ids=frozenset(),
        )

    assert result.action_run_id is None
    spawn_mock.assert_not_called()


def test_select_post_stores_per_candidate_merge_ids(client: TestClient, db: Path) -> None:
    scan = _cached_scan_dict(
        entries=[
            _cached_entry(package="left-pad", tier="auto_merge"),
            _cached_entry(
                package="lodash",
                tier="review_required",
            ),
        ],
        mode="A",
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        client.post(f"/assessment/{_HASH}/plan", follow_redirects=False)
        r = client.post(
            "/select",
            data={
                "selected_candidate_ids": ["cand-left-pad-001", "cand-lodash-001"],
                "auto_merge_candidate_ids": ["cand-left-pad-001"],
            },
            follow_redirects=False,
        )
    assert r.status_code == 303 and r.headers["location"] == "/authorize"
    token = client.cookies.get("arguss_wizard_session")
    assert token
    session = load_session(token, db)
    assert session is not None
    assert session.selected_candidate_ids == ["cand-left-pad-001", "cand-lodash-001"]
    assert session.auto_merge_candidate_ids == ["cand-left-pad-001"]


@pytest.mark.asyncio
async def test_partial_auto_merge_only_tracks_subset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    db: Path,
) -> None:
    work_tree = _work_tree(tmp_path)
    entry_a = _proposal_entry(tier=FixTier.AUTO_MERGE, package="left-pad")
    entry_b = _proposal_entry(tier=FixTier.AUTO_MERGE, package="lodash")
    report = _proposal_report(work_tree, (entry_a, entry_b))
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
    spawn_mock = mock.MagicMock()
    monkeypatch.setattr(mode_c_mod, "spawn_action_merge_task", spawn_mock)
    monkeypatch.setattr(
        github_action_mod,
        "_check_pat_permissions_sync",
        lambda *_a, **_k: PatPermissionResult(sufficient=True, scopes_found=["push"]),
    )
    merge_only = frozenset({entry_a.candidate.candidate_id})
    with (
        mock.patch.object(mode_c_mod, "shallow_clone", return_value=work_tree),
        mock.patch.object(mode_c_mod, "propose_fixes", return_value=report),
        mock.patch.object(
            mode_c_mod,
            "run_mode_c_actions",
            new_callable=AsyncMock,
            return_value=[opened_a, opened_b],
        ),
    ):
        result = await mode_c_mod.execute_scan_with_action(
            url=_EXPRESS_URL,
            pat=_TEST_PAT,
            auto_merge_candidate_ids=merge_only,
        )
    assert result.action_run_id is not None
    spawn_mock.assert_called_once()
    action_run = load_action_run(result.action_run_id, db)
    assert action_run is not None
    tracked_ids = {c.candidate_id for c in action_run.candidates}
    assert tracked_ids == {entry_a.candidate.candidate_id}
