"""Tests for Mode C SSE streaming endpoints."""

from __future__ import annotations

import json
from unittest import mock
from unittest.mock import AsyncMock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.routes as routes_mod
from arguss.api import app as api_app
from arguss.engine.propose import ProposalReport, ProposalSummary
from arguss.web.mode_c_workflow import (
    _STREAM_SENTINEL,
    ScanWithActionResult,
    get_scan_stream_queue,
    register_scan_stream,
)

_SCAN_START = "/scan/with-action/start"
_EXPRESS_URL = "https://github.com/expressjs/express"
_TEST_INSTALLATION_ID = 12345


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def _empty_report() -> ProposalReport:
    return ProposalReport(
        repo_path="/tmp/repo",
        lockfile_path="/tmp/repo/package-lock.json",
        entries=(),
        skipped_findings=(),
        summary=ProposalSummary(
            total_findings=0,
            auto_merge_count=0,
            review_required_count=0,
            decline_count=0,
        ),
    )


def _scan_result() -> ScanWithActionResult:
    from arguss.core.serialization import proposal_report_with_actions_payload

    report = _empty_report()
    return ScanWithActionResult(
        report=report,
        actions=[],
        payload=proposal_report_with_actions_payload(report, []),
        scan_hash="stream-test-hash",
    )


def _parse_sse_events(raw: str) -> list[tuple[str, dict[str, object]]]:
    events: list[tuple[str, dict[str, object]]] = []
    event_name = "message"
    data_lines: list[str] = []
    for line in raw.splitlines():
        if line.startswith("event:"):
            event_name = line.split(":", 1)[1].strip()
        elif line.startswith("data:"):
            data_lines.append(line.split(":", 1)[1].strip())
        elif line == "" and data_lines:
            payload = json.loads("\n".join(data_lines))
            events.append((event_name, payload))
            data_lines = []
    if data_lines:
        payload = json.loads("\n".join(data_lines))
        events.append((event_name, payload))
    return events


@pytest.mark.asyncio
async def test_scan_id_indirection_returns_id_then_streams() -> None:
    scan_id, queue = await register_scan_stream()
    await queue.put({"type": "scan_started", "repo": "o/r"})
    await queue.put(_STREAM_SENTINEL)
    assert scan_id


def test_stream_endpoint_emits_scan_started_first(client: TestClient) -> None:
    async def fake_background(scan_id: str, **kwargs: object) -> None:
        queue = await get_scan_stream_queue(scan_id)
        assert queue is not None
        await queue.put({"type": "scan_started", "repo": "o/r", "ref": "HEAD"})
        await queue.put(
            {
                "type": "scan_complete",
                "total": 0,
                "succeeded": 0,
                "failed": 0,
                "skipped": 0,
            },
        )
        await queue.put(_STREAM_SENTINEL)

    with mock.patch.object(
        routes_mod, "run_scan_background", new_callable=AsyncMock, side_effect=fake_background
    ):
        start = client.post(
            _SCAN_START,
            json={"url": _EXPRESS_URL, "installation_id": _TEST_INSTALLATION_ID},
        )
    assert start.status_code == status.HTTP_200_OK
    scan_id = start.json()["scan_id"]

    stream = client.get(f"/scan/with-action/stream/{scan_id}")
    assert stream.status_code == status.HTTP_200_OK
    events = _parse_sse_events(stream.text)
    assert events[0][0] == "scan_started"
    assert events[0][1]["type"] == "scan_started"


def test_stream_endpoint_emits_action_events_per_candidate(client: TestClient) -> None:
    async def fake_background(scan_id: str, **kwargs: object) -> None:
        queue = await get_scan_stream_queue(scan_id)
        assert queue is not None
        await queue.put(
            {"type": "action_started", "candidate_id": "c1", "package": "a", "from": "1", "to": "2"}
        )
        await queue.put(
            {
                "type": "action_completed",
                "candidate_id": "c1",
                "status": "opened",
                "pr_url": "https://github.com/o/r/pull/1",
                "pr_number": 1,
                "reason": None,
                "package": "a",
                "from": "1",
                "to": "2",
            },
        )
        await queue.put(_STREAM_SENTINEL)

    with mock.patch.object(
        routes_mod, "run_scan_background", new_callable=AsyncMock, side_effect=fake_background
    ):
        scan_id = client.post(
            _SCAN_START,
            json={"url": _EXPRESS_URL, "installation_id": _TEST_INSTALLATION_ID},
        ).json()["scan_id"]

    events = _parse_sse_events(
        client.get(f"/scan/with-action/stream/{scan_id}").text,
    )
    types = [name for name, _ in events]
    assert "action_started" in types
    assert "action_completed" in types


def test_stream_endpoint_emits_scan_complete_at_end(client: TestClient) -> None:
    async def fake_background(scan_id: str, **kwargs: object) -> None:
        queue = await get_scan_stream_queue(scan_id)
        assert queue is not None
        await queue.put(
            {"type": "scan_complete", "total": 1, "succeeded": 1, "failed": 0, "skipped": 0}
        )
        await queue.put(_STREAM_SENTINEL)

    with mock.patch.object(
        routes_mod, "run_scan_background", new_callable=AsyncMock, side_effect=fake_background
    ):
        scan_id = client.post(
            _SCAN_START,
            json={"url": _EXPRESS_URL, "installation_id": _TEST_INSTALLATION_ID},
        ).json()["scan_id"]

    events = _parse_sse_events(
        client.get(f"/scan/with-action/stream/{scan_id}").text,
    )
    assert events[-1][0] == "scan_complete"


def test_stream_endpoint_handles_auth_validation_failure(client: TestClient) -> None:
    async def fake_background(scan_id: str, **kwargs: object) -> None:
        queue = await get_scan_stream_queue(scan_id)
        assert queue is not None
        await queue.put(
            {
                "type": "scan_failed",
                "reason": "arguss-bot does not have access to this repository",
            },
        )
        await queue.put(_STREAM_SENTINEL)

    with mock.patch.object(
        routes_mod, "run_scan_background", new_callable=AsyncMock, side_effect=fake_background
    ):
        scan_id = client.post(
            _SCAN_START,
            json={"url": _EXPRESS_URL, "installation_id": _TEST_INSTALLATION_ID},
        ).json()["scan_id"]

    events = _parse_sse_events(
        client.get(f"/scan/with-action/stream/{scan_id}").text,
    )
    assert any(name == "scan_failed" for name, _ in events)


def test_stream_endpoint_action_failure_emits_failed_event(client: TestClient) -> None:
    async def fake_background(scan_id: str, **kwargs: object) -> None:
        queue = await get_scan_stream_queue(scan_id)
        assert queue is not None
        await queue.put(
            {
                "type": "action_completed",
                "candidate_id": "c1",
                "status": "failed",
                "pr_url": None,
                "pr_number": None,
                "reason": "no lockfile entry",
                "package": "x",
                "from": "1",
                "to": "2",
            },
        )
        await queue.put(_STREAM_SENTINEL)

    with mock.patch.object(
        routes_mod, "run_scan_background", new_callable=AsyncMock, side_effect=fake_background
    ):
        scan_id = client.post(
            _SCAN_START,
            json={"url": _EXPRESS_URL, "installation_id": _TEST_INSTALLATION_ID},
        ).json()["scan_id"]

    events = _parse_sse_events(
        client.get(f"/scan/with-action/stream/{scan_id}").text,
    )
    completed = [p for name, p in events if name == "action_completed"]
    assert completed[0]["status"] == "failed"
