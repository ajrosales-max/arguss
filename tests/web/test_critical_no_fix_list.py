"""UI tests for the critical no-fix findings section on the results page."""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from arguss.engine.skips import no_fix_reason_label
from tests.fixtures.scan_counts_helpers import attach_minimal_scan_counts
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict


def _no_fix_skip_dict(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "kind": "no_fix",
        "advisory_id": "GHSA-nofix-1",
        "package": "vulnerable-pkg",
        "current_version": "1.0.0",
        "title": "Remote code execution",
        "description": "No patch available upstream.",
        "cvss_score": 9.8,
        "severity": "critical",
        "source_url": "https://osv.dev/vulnerability/GHSA-nofix-1",
        "dependency_path": ["root", "vulnerable-pkg"],
        "epss_score": 0.55,
        "epss_percentile": 0.95,
        "is_kev": True,
        "kev_known_ransomware": False,
        "kev_due_date": None,
        "reason": "no_fix_version_in_osv",
        "reason_label": no_fix_reason_label("no_fix_version_in_osv"),
    }
    base.update(overrides)
    return base


def _scan_with_no_fix(*, skips: list[dict[str, Any]], entries: list[dict[str, Any]] | None = None):
    scan = _cached_scan_dict(
        entries=entries or [_cached_entry(package="safe-pkg", tier="auto_merge")]
    )
    scan["skipped_findings"] = skips
    total = len(scan["entries"]) + len(skips)
    scan["summary"]["total_findings"] = total
    return attach_minimal_scan_counts(scan, total_findings=total)


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def test_critical_no_fix_section_renders(client: TestClient) -> None:
    scan = _scan_with_no_fix(skips=[_no_fix_skip_dict()])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.get("/assessment/no-fix-render")
    assert r.status_code == 200
    assert "no-fix-panel" in r.text
    assert "1 package with no automated fix" in r.text
    assert "vulnerable-pkg@1.0.0" in r.text
    assert "Remote code execution" in r.text
    assert "CISA KEV" in r.text


def test_critical_no_fix_sorted_kev_first(client: TestClient) -> None:
    scan = _scan_with_no_fix(
        skips=[
            _no_fix_skip_dict(
                advisory_id="GHSA-high-epss", is_kev=False, epss_score=0.99, title="High EPSS"
            ),
            _no_fix_skip_dict(
                advisory_id="GHSA-kev-first", is_kev=True, epss_score=0.01, title="KEV item"
            ),
        ]
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.get("/assessment/no-fix-sort")
    panel_start = r.text.index("no-fix-panel")
    panel = r.text[panel_start:]
    kev_pos = panel.index("KEV item")
    epss_pos = panel.index("High EPSS")
    assert kev_pos < epss_pos


def test_critical_no_fix_absent_when_empty(client: TestClient) -> None:
    scan = _cached_scan_dict(entries=[_cached_entry()])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.get("/assessment/no-fix-empty")
    assert "Vulnerable — no automated fix" not in r.text


def test_critical_no_fix_has_no_checkboxes(client: TestClient) -> None:
    scan = _scan_with_no_fix(skips=[_no_fix_skip_dict()])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.get("/assessment/no-fix-nocb")
    idx = r.text.index("no-fix-panel")
    chunk = r.text[idx : idx + 2500]
    assert 'type="checkbox"' not in chunk
    assert "candidate-checkbox" not in chunk


def test_tally_shows_no_fix_count(client: TestClient) -> None:
    scan = _scan_with_no_fix(
        skips=[
            _no_fix_skip_dict(),
            _no_fix_skip_dict(advisory_id="GHSA-2", package="other-pkg"),
        ]
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.get("/assessment/no-fix-tally")
    assert "2 no fix" in r.text
