"""Visual polish tests for remediation wizard templates."""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from arguss.settings import settings
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict

_HASH = "wizard-visual-hash"
_TEST_INSTALLATION_ID = 12345


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


@pytest.fixture
def wizard_db(monkeypatch, tmp_path):
    db = tmp_path / "wizard.db"
    monkeypatch.setattr(settings, "db_path", db)
    return db


def _mode_a_scan(*entries: dict[str, Any]) -> dict[str, Any]:
    return _cached_scan_dict(entries=list(entries), mode="A")


def _authorize_html(client: TestClient, wizard_db) -> str:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        client.post(f"/assessment/{_HASH}/plan", follow_redirects=False)
        client.post(
            "/select",
            data={"selected_candidate_ids": ["cand-left-pad-001"]},
            follow_redirects=False,
        )
        response = client.get("/authorize")
    assert response.status_code == status.HTTP_200_OK
    return response.text


def test_plan_page_uses_btn_primary_for_continue(client: TestClient, wizard_db) -> None:
    scan = _mode_a_scan(_cached_entry(package="safe-pkg", tier="auto_merge"))
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        client.post(f"/assessment/{_HASH}/plan", follow_redirects=False)
        response = client.get("/select")
    assert response.status_code == status.HTTP_200_OK
    snippet = response.text.split('id="wizard-plan-continue"')[1][:120]
    assert "btn btn-primary" in snippet


def test_authorize_page_uses_btn_primary_for_create_token_link(
    client: TestClient, wizard_db
) -> None:
    html = _authorize_html(client, wizard_db)
    assert "authorize-github-cta" in html
    assert "btn btn-primary btn-primary-lg" in html
    assert "Create token on GitHub" in html


def test_authorize_page_uses_btn_primary_for_begin(client: TestClient, wizard_db) -> None:
    html = _authorize_html(client, wizard_db)
    snippet = html.split('id="wizard-begin-btn"')[1][:120]
    assert "btn btn-primary btn-primary-lg" in snippet


def test_authorize_page_has_step_1_and_step_2_sections(client: TestClient, wizard_db) -> None:
    html = _authorize_html(client, wizard_db)
    assert "authorize-step-1-heading" in html
    assert "authorize-step-2-heading" in html
    assert "Step 1" in html
    assert "Step 2" in html


def test_authorize_page_has_dual_permission_warning_callout(client: TestClient, wizard_db) -> None:
    html = _authorize_html(client, wizard_db)
    assert "authorize-warning-callout" in html
    assert "Contents and Pull requests" in html


def test_authorize_page_pat_field_is_password_type(client: TestClient, wizard_db) -> None:
    html = _authorize_html(client, wizard_db)
    assert 'id="wizard-pat"' in html
    idx = html.index('id="wizard-pat"')
    assert 'type="password"' in html[idx - 80 : idx + 80]


def test_create_token_link_opens_new_tab(client: TestClient, wizard_db) -> None:
    html = _authorize_html(client, wizard_db)
    idx = html.index('class="btn btn-primary btn-primary-lg authorize-github-cta"')
    block = html[idx : idx + 400]
    assert 'target="_blank"' in block
    assert 'rel="noopener noreferrer"' in block


def test_assessment_plan_tile_after_findings_before_dep_graph(client: TestClient) -> None:
    scan = _mode_a_scan(_cached_entry(package="minimatch", tier="auto_merge"))
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        html = client.get(f"/assessment/{_HASH}").text
    findings_idx = html.index('id="findings-section"')
    cta_idx = html.index('class="remediation-cta')
    dep_idx = html.index('class="dependency-graph-section"')
    assert findings_idx < cta_idx < dep_idx
