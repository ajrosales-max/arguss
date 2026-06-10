"""Visual polish tests for remediation wizard templates."""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict

_HASH = "wizard-visual-hash"
_TEST_PAT = "github_pat_test_token_1234567890abcdef"


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def _mode_a_scan(*entries: dict[str, Any]) -> dict[str, Any]:
    return _cached_scan_dict(entries=list(entries), mode="A")


def _authorize_html(client: TestClient) -> str:
    scan = _mode_a_scan(_cached_entry(package="left-pad", tier="auto_merge"))
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.post(
            f"/results/{_HASH}/authorize",
            data={"selected_candidate_ids": ["cand-left-pad-001"]},
        )
    assert response.status_code == status.HTTP_200_OK
    return response.text


def test_plan_page_uses_btn_primary_for_continue(client: TestClient) -> None:
    scan = _mode_a_scan(_cached_entry(package="safe-pkg", tier="auto_merge"))
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get(f"/results/{_HASH}/plan")
    assert response.status_code == status.HTTP_200_OK
    snippet = response.text.split('id="wizard-plan-continue"')[1][:120]
    assert "btn btn-primary" in snippet


def test_authorize_page_uses_btn_primary_for_create_token_link(client: TestClient) -> None:
    html = _authorize_html(client)
    assert "authorize-github-cta" in html
    assert "btn btn-primary btn-primary-lg" in html
    assert "Create token on GitHub" in html


def test_authorize_page_uses_btn_primary_for_begin(client: TestClient) -> None:
    html = _authorize_html(client)
    snippet = html.split('id="wizard-begin-btn"')[1][:120]
    assert "btn btn-primary btn-primary-lg" in snippet


def test_authorize_page_has_step_1_and_step_2_sections(client: TestClient) -> None:
    html = _authorize_html(client)
    assert "authorize-step-1-heading" in html
    assert "authorize-step-2-heading" in html
    assert "Step 1" in html
    assert "Step 2" in html


def test_authorize_page_has_dual_permission_warning_callout(client: TestClient) -> None:
    html = _authorize_html(client)
    assert "authorize-warning-callout" in html
    assert "Contents and Pull requests" in html


def test_authorize_page_pat_field_is_password_type(client: TestClient) -> None:
    html = _authorize_html(client)
    assert 'id="wizard-pat"' in html
    idx = html.index('id="wizard-pat"')
    assert 'type="password"' in html[idx - 80 : idx + 80]


def test_create_token_link_opens_new_tab(client: TestClient) -> None:
    html = _authorize_html(client)
    idx = html.index('class="btn btn-primary btn-primary-lg authorize-github-cta"')
    block = html[idx : idx + 400]
    assert 'target="_blank"' in block
    assert 'rel="noopener noreferrer"' in block


def test_assessment_plan_tile_after_findings_before_dep_graph(client: TestClient) -> None:
    scan = _mode_a_scan(_cached_entry(package="minimatch", tier="auto_merge"))
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        html = client.get(f"/results/{_HASH}").text
    findings_idx = html.index('class="findings-section"')
    cta_idx = html.index('class="remediation-cta"')
    dep_idx = html.index('class="placeholder-section"')
    assert findings_idx < cta_idx < dep_idx
