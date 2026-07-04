"""Tests for Mode C action-run dashboard HTMX partial."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from arguss.web.action_runs import (
    add_action_run_candidate,
    create_action_run,
    mark_action_run_completed,
)


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "dashboard.db"
    monkeypatch.setattr(dashboard_mod.settings, "db_path", path)
    return path


def _cached_scan(*, scan_hash: str = "abc" * 21 + "a") -> dict[str, Any]:
    return {
        "scan_meta": {"repo_display": "expressjs/express", "mode": "C", "ref": "main"},
        "entries": [],
        "summary": {"total_findings": 0, "total_candidates": 0},
    }


def test_action_run_progress_partial_200(client: TestClient, db: Path) -> None:
    run = create_action_run("scan-hash", "C", db, scan_ref="main")
    add_action_run_candidate(
        run.id,
        "c1",
        "left-pad",
        "1.3.0",
        "1.3.1",
        db,
        pr_number=42,
        state="ci_running",
    )
    with mock.patch.object(dashboard_mod, "_load_cached_results", return_value=_cached_scan()):
        response = client.get(f"/dashboard/action-run/{run.id}")

    assert response.status_code == status.HTTP_200_OK
    assert "Auto-merge progress" in response.text
    assert "left-pad" in response.text
    assert "PR #42" in response.text
    assert "ci running" in response.text.lower()
    assert 'hx-trigger="every 5s"' in response.text


def test_action_run_progress_stops_polling_when_terminal(client: TestClient, db: Path) -> None:
    run = create_action_run("scan-hash", "C", db)
    cand = add_action_run_candidate(run.id, "c1", "pkg", "1", "2", db, pr_number=1)
    mark_action_run_completed(run.id, db)
    import arguss.web.action_runs as ar

    ar.update_action_run_candidate(cand.id, db, state="merged")

    with mock.patch.object(dashboard_mod, "_load_cached_results", return_value=_cached_scan()):
        response = client.get(f"/dashboard/action-run/{run.id}")

    assert response.status_code == status.HTTP_200_OK
    assert 'hx-trigger="every 5s"' not in response.text
    assert "Merge wait finished" in response.text


def test_action_run_progress_not_found(client: TestClient) -> None:
    response = client.get("/dashboard/action-run/00000000-0000-4000-8000-000000000001")
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_no_checks_primary_and_secondary_in_progress_partial(
    client: TestClient,
    db: Path,
) -> None:
    from arguss.web.action_runs import merge_escalation_primary_detail

    run = create_action_run("scan-hash", "C", db, scan_ref="main")
    primary = merge_escalation_primary_detail("no_checks")
    add_action_run_candidate(
        run.id,
        "c1",
        "left-pad",
        "1.3.0",
        "1.3.1",
        db,
        pr_number=42,
        state="no_checks",
        state_detail=primary,
    )
    with mock.patch.object(dashboard_mod, "_load_cached_results", return_value=_cached_scan()):
        response = client.get(f"/dashboard/action-run/{run.id}")

    assert response.status_code == status.HTTP_200_OK
    assert html.unescape(primary) in html.unescape(response.text)
    assert (
        "No check runs were observed on the head commit within the grace period." in response.text
    )
