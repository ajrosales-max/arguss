"""Shared fixtures for web route tests."""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.settings import settings


@pytest.fixture
def wizard_db(tmp_path, monkeypatch):
    db = tmp_path / "wizard.sqlite"
    monkeypatch.setattr(settings, "db_path", db)
    return db


def open_wizard_select(
    client: TestClient,
    scan_hash: str,
    scan: dict[str, Any],
    *,
    wizard_db: object = None,
) -> Any:
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        plan = client.post(f"/assessment/{scan_hash}/plan", follow_redirects=False)
    assert plan.status_code == 303
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        return client.get("/select")


def post_wizard_select(
    client: TestClient,
    selected_ids: list[str],
) -> Any:
    return client.post(
        "/select",
        data={"selected_candidate_ids": selected_ids},
        follow_redirects=True,
    )


def post_wizard_authorize(client: TestClient, pat: str) -> Any:
    return client.post("/authorize", data={"pat": pat}, follow_redirects=False)
