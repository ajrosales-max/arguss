"""Integration tests for wizard-scoped Mode C actions (phases 2 & 4)."""

from __future__ import annotations

from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, status
from fastapi.testclient import TestClient

import arguss.web.github_action as github_action_mod
import arguss.web.mode_c_workflow as mode_c_mod
import arguss.web.routes as routes_mod
from arguss.api import app as api_app
from arguss.core.models import FixTier
from arguss.core.serialization import proposal_report_with_actions_payload
from arguss.web.github_action import ActionResult
from arguss.web.mode_c_workflow import (
    ScanWithActionResult,
    execute_scan_with_action,
    register_scan_stream,
)
from tests.test_scan_with_action_endpoint import (
    _EXPRESS_URL,
    _TEST_INSTALLATION_ID,
    _proposal_entry,
    _proposal_report,
)

_SCAN_WITH_ACTION = "/scan/with-action"
_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "lockfiles"


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def _work_tree(tmp_path: Path) -> Path:
    lockfile = _FIXTURES / "minimal.json"
    (tmp_path / "package-lock.json").write_bytes(lockfile.read_bytes())
    return tmp_path


def _auto_merge_report(tmp_path: Path, packages: tuple[str, ...]):
    entries = tuple(_proposal_entry(tier=FixTier.AUTO_MERGE, package=pkg) for pkg in packages)
    return _proposal_report(tmp_path, entries)


@pytest.mark.asyncio
async def test_action_acts_on_selected_candidates_only(tmp_path: Path) -> None:
    work_tree = _work_tree(tmp_path)
    report = _auto_merge_report(work_tree, ("pkg-a", "pkg-b"))
    selected_id = report.entries[0].candidate.candidate_id
    captured: list = []

    async def fake_run_mode_c_actions(entries, *args, **kwargs):
        captured.extend(list(entries))
        return []

    with (
        mock.patch.object(mode_c_mod, "shallow_clone", return_value=work_tree),
        mock.patch.object(mode_c_mod, "propose_fixes", return_value=report),
        mock.patch.object(mode_c_mod, "run_mode_c_actions", side_effect=fake_run_mode_c_actions),
    ):
        await execute_scan_with_action(
            url=_EXPRESS_URL,
            installation_id=_TEST_INSTALLATION_ID,
            selected_candidate_ids=[selected_id],
        )

    assert len(captured) == 1
    assert captured[0].candidate.candidate_id == selected_id


@pytest.mark.asyncio
async def test_action_rejects_unknown_candidate_id(tmp_path: Path) -> None:
    work_tree = _work_tree(tmp_path)
    report = _auto_merge_report(work_tree, ("only",))
    ghost_id = "ghost-unknown-id"

    with (
        mock.patch.object(mode_c_mod, "shallow_clone", return_value=work_tree),
        mock.patch.object(mode_c_mod, "propose_fixes", return_value=report),
        pytest.raises(HTTPException) as exc_info,
    ):
        await execute_scan_with_action(
            url=_EXPRESS_URL,
            installation_id=_TEST_INSTALLATION_ID,
            selected_candidate_ids=[ghost_id],
        )

    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_action_accepts_review_required_candidate_id(tmp_path: Path) -> None:
    work_tree = _work_tree(tmp_path)
    review = _proposal_entry(tier=FixTier.REVIEW_REQUIRED, package="chalk")
    report = _proposal_report(work_tree, (review,))
    captured: list = []

    async def fake_run_mode_c_actions(entries, *args, **kwargs):
        captured.extend(list(entries))
        return []

    with (
        mock.patch.object(mode_c_mod, "shallow_clone", return_value=work_tree),
        mock.patch.object(mode_c_mod, "propose_fixes", return_value=report),
        mock.patch.object(mode_c_mod, "run_mode_c_actions", side_effect=fake_run_mode_c_actions),
    ):
        await execute_scan_with_action(
            url=_EXPRESS_URL,
            installation_id=_TEST_INSTALLATION_ID,
            selected_candidate_ids=[review.candidate.candidate_id],
        )

    assert len(captured) == 1
    assert captured[0].candidate.package == "chalk"


@pytest.mark.asyncio
async def test_action_none_selection_falls_back_to_all_auto_merge(tmp_path: Path) -> None:
    work_tree = _work_tree(tmp_path)
    report = _auto_merge_report(work_tree, ("a", "b"))
    captured: list = []

    async def fake_run_mode_c_actions(entries, *args, **kwargs):
        captured.extend(list(entries))
        return []

    with (
        mock.patch.object(mode_c_mod, "shallow_clone", return_value=work_tree),
        mock.patch.object(mode_c_mod, "propose_fixes", return_value=report),
        mock.patch.object(mode_c_mod, "run_mode_c_actions", side_effect=fake_run_mode_c_actions),
    ):
        await execute_scan_with_action(
            url=_EXPRESS_URL,
            installation_id=_TEST_INSTALLATION_ID,
            selected_candidate_ids=None,
        )

    assert len(captured) == 2


@pytest.mark.asyncio
async def test_rescan_selection_unknown_id_returns_400(tmp_path: Path) -> None:
    work_tree = _work_tree(tmp_path)
    auto = _proposal_entry(tier=FixTier.AUTO_MERGE, package="left-pad")
    review = _proposal_entry(tier=FixTier.REVIEW_REQUIRED, package="chalk")
    report = _proposal_report(work_tree, (auto, review))

    with (
        mock.patch.object(mode_c_mod, "shallow_clone", return_value=work_tree),
        mock.patch.object(mode_c_mod, "propose_fixes", return_value=report),
        pytest.raises(HTTPException) as exc_info,
    ):
        await execute_scan_with_action(
            url=_EXPRESS_URL,
            installation_id=_TEST_INSTALLATION_ID,
            selected_candidate_ids=["missing-candidate-id"],
        )

    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_sse_review_required_selection_succeeds(tmp_path: Path) -> None:
    work_tree = _work_tree(tmp_path)
    auto = _proposal_entry(tier=FixTier.AUTO_MERGE, package="a")
    review = _proposal_entry(tier=FixTier.REVIEW_REQUIRED, package="b")
    report = _proposal_report(work_tree, (auto, review))
    scan_id, queue = await register_scan_stream()

    with (
        mock.patch.object(mode_c_mod, "shallow_clone", return_value=work_tree),
        mock.patch.object(mode_c_mod, "propose_fixes", return_value=report),
        mock.patch.object(
            mode_c_mod, "run_mode_c_actions", new_callable=AsyncMock, return_value=[]
        ),
    ):
        await mode_c_mod.run_scan_background(
            scan_id,
            url=_EXPRESS_URL,
            installation_id=_TEST_INSTALLATION_ID,
            selected_candidate_ids=[review.candidate.candidate_id],
        )

    failed_events: list[dict] = []
    while True:
        item = await queue.get()
        if item is mode_c_mod._STREAM_SENTINEL:
            break
        if isinstance(item, dict) and item.get("type") == "scan_failed":
            failed_events.append(item)

    assert failed_events == []


def test_existing_blocking_endpoint_unchanged(client: TestClient, tmp_path: Path) -> None:
    work_tree = _work_tree(tmp_path)
    report = _auto_merge_report(work_tree, ("left-pad",))
    opened = ActionResult(
        candidate_id=report.entries[0].candidate.candidate_id,
        status="opened",
        pr_url="https://github.com/o/r/pull/1",
        pr_number=1,
        reason=None,
    )
    payload = proposal_report_with_actions_payload(report, [opened])
    payload["executive_summary"] = None
    result = ScanWithActionResult(
        report=report,
        actions=[opened],
        payload=payload,
        scan_hash="hash",
    )

    with mock.patch.object(
        routes_mod,
        "execute_scan_with_action",
        new_callable=AsyncMock,
        return_value=result,
    ) as execute_mock:
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL, "installation_id": _TEST_INSTALLATION_ID},
        )

    assert response.status_code == status.HTTP_200_OK
    execute_mock.assert_awaited_once()
    assert execute_mock.call_args.kwargs.get("selected_candidate_ids") is None


@pytest.mark.asyncio
async def test_actions_planned_count_matches_selected_subset(tmp_path: Path) -> None:
    """SSE actions_planned.count reflects filtered selection, not all AUTO_MERGE."""
    work_tree = _work_tree(tmp_path)
    report = _auto_merge_report(work_tree, ("pkg-a", "pkg-b"))
    selected_id = report.entries[0].candidate.candidate_id
    events: list[dict[str, object]] = []

    async def emit(event: dict[str, object]) -> None:
        events.append(event)

    opened = ActionResult(
        candidate_id=selected_id,
        status="opened",
        pr_url=None,
        pr_number=None,
        reason=None,
    )

    with (
        mock.patch.object(mode_c_mod, "shallow_clone", return_value=work_tree),
        mock.patch.object(mode_c_mod, "propose_fixes", return_value=report),
        mock.patch.object(github_action_mod, "open_fix_pr", return_value=opened),
    ):
        await execute_scan_with_action(
            url=_EXPRESS_URL,
            installation_id=_TEST_INSTALLATION_ID,
            selected_candidate_ids=[selected_id],
            event_emitter=emit,
        )

    planned = [e for e in events if e.get("type") == "actions_planned"]
    assert len(planned) == 1
    assert planned[0]["count"] == 1
    candidates = planned[0]["candidates"]
    assert isinstance(candidates, list)
    assert len(candidates) == 1
    assert candidates[0]["candidate_id"] == selected_id
    assert "fix_kind" in candidates[0]


def test_streaming_start_passes_selected_candidate_ids(client: TestClient) -> None:
    captured: dict[str, object] = {}

    async def fake_background(scan_id: str, **kwargs: object) -> None:
        captured.update(kwargs)
        queue = await mode_c_mod.get_scan_stream_queue(scan_id)
        assert queue is not None
        await queue.put(mode_c_mod._STREAM_SENTINEL)

    with mock.patch.object(
        routes_mod,
        "run_scan_background",
        new_callable=AsyncMock,
        side_effect=fake_background,
    ):
        response = client.post(
            "/scan/with-action/start",
            json={
                "url": _EXPRESS_URL,
                "installation_id": _TEST_INSTALLATION_ID,
                "selected_candidate_ids": ["cand-pkg-a-001"],
            },
        )

    assert response.status_code == status.HTTP_200_OK
    assert captured.get("selected_candidate_ids") == ["cand-pkg-a-001"]


@pytest.mark.asyncio
async def test_same_ref_rescan_preserves_candidate_ids(tmp_path: Path) -> None:
    work_tree = _work_tree(tmp_path)
    report = _auto_merge_report(work_tree, ("left-pad",))
    selected_id = report.entries[0].candidate.candidate_id
    with (
        mock.patch.object(mode_c_mod, "shallow_clone", return_value=work_tree),
        mock.patch.object(mode_c_mod, "propose_fixes", return_value=report),
        mock.patch.object(mode_c_mod, "run_mode_c_actions", return_value=[]),
        mock.patch.object(mode_c_mod, "save_scan_inputs"),
        mock.patch.object(mode_c_mod, "scan_input_hash", return_value="hash"),
    ):
        result = await execute_scan_with_action(
            url=_EXPRESS_URL,
            installation_id=_TEST_INSTALLATION_ID,
            ref="v1.0.0",
            assessment_ref="v1.0.0",
            selected_candidate_ids=[selected_id],
        )
    assert [e.candidate.candidate_id for e in result.report.entries] == [selected_id]
