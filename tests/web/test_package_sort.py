"""Tests for package sort data attributes and severity sort logic."""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from arguss.web.results_context import build_packages
from tests.fixtures.scan_counts_helpers import attach_minimal_scan_counts
from tests.test_candidate_selection_ui import _cached_scan_dict


def _cached_entry_with_cvss(
    *,
    package: str,
    cvss_score: float,
    tier: str = "review_required",
    suffix: str = "001",
) -> dict[str, Any]:
    cid = f"cand-{package}-{suffix}"
    return {
        "finding": {
            "severity": "critical" if cvss_score >= 9.0 else "high",
            "is_kev": False,
            "cvss_score": cvss_score,
            "dependency": {"path": ["root", package], "direct": False, "version": "1.0.0"},
            "title": f"Test advisory for {package}",
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
            "veto_signals": (),
            "reasons": ["test reason"],
            "candidate_id": cid,
        },
    }


def _two_package_sort_scan() -> dict[str, Any]:
    entries = [
        _cached_entry_with_cvss(package="pkg-high-cvss", cvss_score=9.8, suffix="001"),
        *[
            _cached_entry_with_cvss(
                package="pkg-many-findings",
                cvss_score=5.0,
                suffix=f"{i:03d}",
            )
            for i in range(1, 6)
        ],
    ]
    return attach_minimal_scan_counts(_cached_scan_dict(entries=entries), total_findings=6)


def _severity_sort_key(row: dict[str, Any]) -> tuple[float, int, str]:
    max_cvss = float(row["max_cvss"]) if row["max_cvss"] is not None else -1.0
    return (-max_cvss, -int(row["findings"]), row["name"])


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def test_build_packages_exposes_max_cvss_from_rollups() -> None:
    scan = _two_package_sort_scan()
    packages = build_packages(scan, scan_hash="sort-test")
    by_name = {pkg.name: pkg for pkg in packages}
    assert by_name["pkg-high-cvss"].max_cvss == 9.8
    assert by_name["pkg-high-cvss"].total_count == 1
    assert by_name["pkg-many-findings"].max_cvss == 5.0
    assert by_name["pkg-many-findings"].total_count == 5


def test_severity_sort_comparator_orders_by_cvss_then_findings() -> None:
    rows = [
        {"name": "pkg-high-cvss", "max_cvss": 9.8, "findings": 1},
        {"name": "pkg-many-findings", "max_cvss": 5.0, "findings": 5},
    ]
    ordered = [row["name"] for row in sorted(rows, key=_severity_sort_key)]
    assert ordered[0] == "pkg-high-cvss"


def test_finding_count_sort_orders_by_findings_desc() -> None:
    rows = [
        {"name": "pkg-high-cvss", "max_cvss": 9.8, "findings": 1},
        {"name": "pkg-many-findings", "max_cvss": 5.0, "findings": 5},
    ]
    ordered = [row["name"] for row in sorted(rows, key=lambda r: (-int(r["findings"]), r["name"]))]
    assert ordered[0] == "pkg-many-findings"


def test_results_page_has_severity_sort_and_data_max_cvss(client: TestClient) -> None:
    scan = _two_package_sort_scan()
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/sort-demo")

    assert response.status_code == status.HTTP_200_OK
    text = response.text
    assert 'value="severity"' in text
    assert 'value="findings"' in text
    assert "Finding count" in text
    assert 'data-max-cvss="9.8"' in text
    assert 'data-max-cvss="5.0"' in text
    assert "dataset.maxCvss" in text
    assert "Number(b.dataset.findings) - Number(a.dataset.findings)" in text
    assert 'value="default"' in text
    assert 'value="trust"' in text
    assert 'value="epss"' in text
    assert "dataset.sortDefault" in text
    assert "sortPackages(select.value)" in text
