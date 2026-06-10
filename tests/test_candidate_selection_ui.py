"""UI tests for Scan results candidate selection and entry-point reshaping."""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from tests.web.conftest import open_wizard_select

_EXPRESS_URL = "https://github.com/expressjs/express"
_FIXED_TIME = "2026-05-18T12:00:00+00:00"


def _cached_entry(
    *,
    package: str = "path-to-regexp",
    tier: str = "review_required",
    veto_signals: tuple[str, ...] = (),
) -> dict[str, Any]:
    cid = f"cand-{package}-001"
    return {
        "finding": {
            "severity": "high",
            "is_kev": False,
            "dependency": {"path": ["root", package], "direct": False, "version": "1.0.0"},
            "title": "Test advisory",
            "remediation": "Upgrade package",
            "source_url": "https://github.com/advisories/GHSA-test",
            "epss_score": 0.21,
            "epss_percentile": 0.9,
        },
        "candidate": {
            "package": package,
            "from_version": "1.0.0",
            "to_version": "1.0.1",
            "fix_kind": "patch",
            "trust_subscore": 50,
            "max_epss_score": 0.21,
            "candidate_id": cid,
        },
        "verdict": {
            "score": 40,
            "tier": tier,
            "veto_signals": veto_signals,
            "reasons": ["test reason"],
            "candidate_id": cid,
        },
    }


def _cached_scan_dict(*, entries: list[dict[str, Any]], mode: str = "A") -> dict[str, Any]:
    return {
        "entries": entries,
        "skipped_findings": [],
        "summary": {
            "total_findings": len(entries),
            "total_candidates": len(entries),
            "auto_merge_count": sum(1 for e in entries if e["verdict"]["tier"] == "auto_merge"),
            "review_required_count": sum(
                1 for e in entries if e["verdict"]["tier"] == "review_required"
            ),
            "decline_count": sum(1 for e in entries if e["verdict"]["tier"] == "decline"),
            "kev_count": 0,
            "max_epss_score": 0.21,
        },
        "project_scores": {
            "prs": 62,
            "vulnerability_subscore": 70,
            "trust_subscore": 50,
            "pipeline_subscore": 100,
            "test_reality": "vetoed",
        },
        "executive_summary": "Test executive summary.",
        "lens_explain": {"pipeline": {"workflow_files": [".github/workflows/ci.yml"]}},
        "scan_meta": {
            "repo_display": "expressjs/express",
            "ref": "HEAD",
            "mode": mode,
            "completed_at": _FIXED_TIME,
            "dep_counts": {"direct": 2, "transitive": 5},
        },
    }


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def test_scan_page_has_scan_and_upload_entry_tabs(client: TestClient) -> None:
    response = client.get("/scan")
    assert response.status_code == status.HTTP_200_OK
    text = response.text
    assert "mode-tab" in text
    assert "Upload" in text
    mode_tabs = text.split('class="mode-tabs"', 1)[1].split("</div>", 1)[0]
    assert "Scan with action" not in mode_tabs


def test_scan_results_page_has_plan_cta_not_selection(client: TestClient) -> None:
    scan = _cached_scan_dict(
        entries=[
            _cached_entry(package="minimatch", tier="auto_merge"),
        ],
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/cta-demo")
    assert response.status_code == status.HTTP_200_OK
    assert "Plan remediation" in response.text
    assert "/assessment/cta-demo/plan" in response.text
    assert 'id="candidate-selection"' not in response.text


def test_plan_page_renders_selection_checkboxes(client: TestClient, wizard_db) -> None:
    scan = _cached_scan_dict(
        entries=[
            _cached_entry(package="minimatch", tier="auto_merge"),
            _cached_entry(
                package="lodash", tier="review_required", veto_signals=("pipeline.test_reality",)
            ),
        ],
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = open_wizard_select(client, "selection-demo", scan)

    assert response.status_code == status.HTTP_200_OK
    assert 'name="selected_candidate_ids"' in response.text
    assert 'id="candidate-selection"' in response.text
    assert "AUTO_MERGE" in response.text
    assert "REVIEW_REQUIRED" in response.text


def test_plan_page_auto_merge_checked_by_default(client: TestClient, wizard_db) -> None:
    scan = _cached_scan_dict(
        entries=[
            _cached_entry(package="safe-pkg", tier="auto_merge"),
            _cached_entry(package="review-pkg", tier="review_required"),
        ],
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = open_wizard_select(client, "auto-merge-default", scan)

    text = response.text
    auto_idx = text.index('value="cand-safe-pkg-001"')
    review_idx = text.index('value="cand-review-pkg-001"')
    assert "checked" in text[auto_idx : auto_idx + 200]
    assert "checked" not in text[review_idx : review_idx + 200]


def test_plan_page_review_required_unchecked_by_default(client: TestClient, wizard_db) -> None:
    scan = _cached_scan_dict(
        entries=[_cached_entry(package="needs-review", tier="review_required")]
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = open_wizard_select(client, "review-default", scan)

    idx = response.text.index('value="cand-needs-review-001"')
    assert "checked" not in response.text[idx : idx + 120]


def test_plan_page_continue_disabled_until_selection(client: TestClient, wizard_db) -> None:
    scan = _cached_scan_dict(
        entries=[_cached_entry(package="needs-review", tier="review_required")]
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = open_wizard_select(client, "disabled-action", scan)

    assert 'id="wizard-plan-continue"' in response.text
    btn_part = response.text.split('id="wizard-plan-continue"')[1].split(">")[0]
    assert "disabled" in btn_part


def test_upload_results_page_has_no_action_button(client: TestClient) -> None:
    scan = _cached_scan_dict(entries=[_cached_entry(package="left-pad")], mode="B")
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/upload-no-action")

    assert 'id="action-selected-btn"' not in response.text
    assert 'id="candidate-selection"' not in response.text


def test_upload_results_page_has_no_selection_checkboxes(client: TestClient) -> None:
    scan = _cached_scan_dict(entries=[_cached_entry(package="left-pad")], mode="B")
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/upload-no-select")

    assert 'name="selected_candidate_ids"' not in response.text
    assert "/scan" in response.text


def test_scan_url_endpoint_unchanged(client: TestClient) -> None:
    response = client.post("/scan/url", json={"url": _EXPRESS_URL, "ref": "HEAD"})
    assert response.status_code != status.HTTP_404_NOT_FOUND
