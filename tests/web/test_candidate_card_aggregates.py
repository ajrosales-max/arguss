"""Candidate finding cards use scan_counts aggregates, not primary-finding EPSS alone."""

from __future__ import annotations

import re
from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from tests.fixtures.scan_counts_helpers import attach_minimal_scan_counts
from tests.test_candidate_selection_ui import _cached_scan_dict


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def _tar_scan_with_misleading_primary_epss() -> dict[str, Any]:
    """Primary finding EPSS 0.0; sibling 0.85 — card must show aggregate max."""
    cid = "cand-tar-620"
    related: list[dict[str, Any]] = [
        {
            "advisory_id": "GHSA-tar-a",
            "finding_id": "fid-tar-a",
            "title": "GHSA-tar-a: low epss primary",
            "severity": "high",
            "cvss_score": 7.5,
            "epss_score": 0.0,
            "epss_percentile": 0.1,
            "is_kev": False,
            "dependency": {
                "name": "tar",
                "version": "6.2.0",
                "path": ["root", "tar"],
                "direct": False,
            },
        },
        {
            "advisory_id": "GHSA-tar-b",
            "finding_id": "fid-tar-b",
            "title": "GHSA-tar-b: high epss sibling",
            "severity": "critical",
            "cvss_score": 8.8,
            "epss_score": 0.85,
            "epss_percentile": 0.97,
            "is_kev": False,
            "dependency": {
                "name": "tar",
                "version": "6.2.0",
                "path": ["root", "tar"],
                "direct": False,
            },
        },
    ]
    entry = {
        "finding": related[0],
        "related_findings": related,
        "candidate": {
            "package": "tar",
            "from_version": "6.2.0",
            "to_version": "6.2.1",
            "fix_kind": "patch",
            "trust_subscore": 80,
            "candidate_id": cid,
        },
        "verdict": {
            "score": 35,
            "tier": "auto_merge",
            "veto_signals": [],
            "reasons": ["tar regression"],
            "candidate_id": cid,
        },
    }
    scan = _cached_scan_dict(entries=[entry])
    scan["scan_counts"] = {
        **scan["scan_counts"],
        "total_findings": 2,
        "total_candidates": 1,
        "candidates": [
            {
                "candidate_id": cid,
                "package": "tar",
                "from_version": "6.2.0",
                "to_version": "6.2.1",
                "tier": "auto_merge",
                "related_finding_ids": ["fid-tar-a", "fid-tar-b"],
                "aggregates": {
                    "max_epss_score": 0.85,
                    "max_epss_percentile": 0.97,
                    "max_cvss_score": 8.8,
                    "has_kev": False,
                    "severity_min": "high",
                    "severity_max": "critical",
                },
            }
        ],
    }
    return attach_minimal_scan_counts(scan, total_findings=2)


def _tar_assessment_html(client: TestClient) -> str:
    scan = _tar_scan_with_misleading_primary_epss()
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/tar-card-aggregates")
    assert response.status_code == status.HTTP_200_OK
    return response.text


def test_candidate_card_shows_max_epss_not_primary_zero(client: TestClient) -> None:
    text = _tar_assessment_html(client)
    assert "Max EPSS 85.0%" in text
    assert re.search(r"Max EPSS 0\.0%", text) is None
    assert re.search(r"EPSS 0\.0% probability", text) is None


def test_candidate_card_shows_max_cvss_and_finding_count(client: TestClient) -> None:
    text = _tar_assessment_html(client)
    assert "Max CVSS 8.8 · 2 findings" in text


def test_advisory_rows_show_per_advisory_epss(client: TestClient) -> None:
    text = _tar_assessment_html(client)
    assert "EPSS 0.0%" in text
    assert "EPSS 85.0%" in text


def test_card_max_epss_matches_max_over_advisory_rows(client: TestClient) -> None:
    text = _tar_assessment_html(client)
    advisory_epss = [
        float(m.group(1))
        for m in re.finditer(
            r"package-advisory-card[\s\S]*?EPSS (\d+(?:\.\d+)?)%",
            text,
        )
    ]
    assert advisory_epss
    assert max(advisory_epss) == pytest.approx(85.0)
    assert "Max EPSS 85.0%" in text
