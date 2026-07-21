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
from tests.web.session_helpers import make_session_client, seed_github_installation

_HASH = "wizard-visual-hash"
_TEST_INSTALLATION_ID = 12345


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


@pytest.fixture
def session_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    return make_session_client(monkeypatch)


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


def test_authorize_page_uses_btn_primary_for_connect_cta(client: TestClient, wizard_db) -> None:
    html = _authorize_html(client, wizard_db)
    assert "authorize-github-cta" in html
    assert "btn btn-primary btn-primary-lg" in html
    assert "Connect arguss-bot on GitHub" in html


def test_authorize_page_uses_btn_primary_for_begin_when_connected(
    session_client: TestClient, wizard_db
) -> None:
    seed_github_installation(session_client, _TEST_INSTALLATION_ID)
    html = _authorize_html(session_client, wizard_db)
    snippet = html.split('id="wizard-begin-btn"')[1][:120]
    assert "btn btn-primary btn-primary-lg" in snippet


def test_authorize_page_has_no_pat_field(client: TestClient, wizard_db) -> None:
    html = _authorize_html(client, wizard_db)
    assert 'name="pat"' not in html
    assert 'id="wizard-pat"' not in html
    assert 'type="password"' not in html


def test_connect_cta_links_to_github_install_same_tab(client: TestClient, wizard_db) -> None:
    """CTA carries the authorize page as an explicit internal ?next= return path."""
    html = _authorize_html(client, wizard_db)
    idx = html.index("authorize-github-cta")
    block = html[idx : idx + 400]
    assert 'href="/github/install?next=/authorize"' in block
    assert 'target="_blank"' not in block


def test_assessment_plan_tile_after_findings_before_dep_graph(client: TestClient) -> None:
    scan = _mode_a_scan(_cached_entry(package="minimatch", tier="auto_merge"))
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        html = client.get(f"/assessment/{_HASH}").text
    findings_idx = html.index('id="findings-section"')
    cta_idx = html.index('class="remediation-cta')
    dep_idx = html.index('class="dependency-graph-section"')
    assert findings_idx < cta_idx < dep_idx
