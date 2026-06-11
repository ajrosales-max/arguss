"""Tests for deepened per-finding rows on /select."""

from __future__ import annotations

from unittest import mock

import pytest
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from arguss.web.results_context import (
    ResultsFindingView,
    _finding_view_from_dict,
    build_candidates_by_tier,
)
from tests.test_candidate_selection_ui import _cached_scan_dict
from tests.web.conftest import open_wizard_select
from tests.web.test_candidate_findings_drilldown import _entry, _rf


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def _depth_finding(**overrides):
    base = {
        "advisory_id": "GHSA-test-0001",
        "title": "GHSA-test-0001: Example advisory",
        "cvss_score": 7.5,
        "severity": "high",
        "source_url": "https://osv.dev/vulnerability/GHSA-test-0001",
        "dependency": {"name": "lodash", "version": "4.17.20"},
        "lens": "cve",
        "score": 75,
        "description": "A detailed vulnerability write-up.",
        "fixed_versions": ["4.17.21"],
        "published_at": "2024-03-15",
    }
    base.update(overrides)
    return base


def test_finding_view_carries_description_when_available():
    view = _finding_view_from_dict(_depth_finding())
    assert view is not None
    assert view.description_html is not None
    assert "A detailed vulnerability write-up." in view.description_html


def test_finding_view_carries_fixed_range_when_available():
    view = _finding_view_from_dict(_depth_finding())
    assert view is not None
    assert view.fixed_range == "≥ 4.17.21"


def test_finding_view_carries_published_at_when_available():
    view = _finding_view_from_dict(_depth_finding())
    assert view is not None
    assert view.published_at == "2024-03-15"


def test_finding_view_severity_optional():
    view = _finding_view_from_dict(_depth_finding(severity=None))
    assert view is not None
    assert view.severity is None


def test_finding_view_handles_findings_with_no_description():
    view = _finding_view_from_dict(_depth_finding(description=""))
    assert view is not None
    assert view.description_html is None


def test_single_finding_toggle_text_is_singular(client, wizard_db):
    scan = _cached_scan_dict(entries=[_entry("left-pad", [_rf("GHSA-one", 5)])])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = open_wizard_select(client, "single-singular", scan)
    assert "▸ 1 finding" in r.text
    assert "1 findings" not in r.text


def test_finding_row_renders_severity_badge_when_present(client, wizard_db):
    f = _rf("GHSA-sev", 8)
    f["severity"] = "critical"
    scan = _cached_scan_dict(entries=[_entry("pkg", [f])])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = open_wizard_select(client, "severity-badge", scan)
    assert "finding-severity-critical" in r.text


def test_finding_row_renders_description_when_present(client, wizard_db):
    f = _rf("GHSA-desc", 6)
    f["description"] = "Long advisory narrative."
    scan = _cached_scan_dict(entries=[_entry("pkg", [f])])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = open_wizard_select(client, "description", scan)
    assert "finding-description-wrap" in r.text
    assert 'data-truncated="true"' in r.text
    assert "Long advisory narrative." in r.text
    assert "finding-description-toggle" in r.text


def test_finding_row_omits_description_section_when_absent(client, wizard_db):
    f = _rf("GHSA-nodesc", 6)
    f["description"] = ""
    scan = _cached_scan_dict(entries=[_entry("pkg", [f])])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = open_wizard_select(client, "no-description", scan)
    assert '<div class="finding-description-wrap">' not in r.text


def test_finding_row_renders_fixed_range_when_present(client, wizard_db):
    scan = _cached_scan_dict(entries=[_entry("pkg", [_rf("GHSA-fix", 7)])])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = open_wizard_select(client, "fixed-range", scan)
    assert "finding-versions" in r.text
    assert "≥ 2.0.0" in r.text


def test_finding_row_includes_ai_placeholder_slot(client, wizard_db):
    scan = _cached_scan_dict(entries=[_entry("pkg", [_rf("GHSA-ai", 5)])])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = open_wizard_select(client, "ai-slot", scan)
    assert "finding-ai-analysis-slot" in r.text
    assert "AI analysis of this fix coming soon." in r.text


def test_finding_ai_placeholder_has_finding_id_hook(client, wizard_db):
    scan = _cached_scan_dict(entries=[_entry("pkg", [_rf("GHSA-hook", 5)])])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = open_wizard_select(client, "ai-hook", scan)
    assert 'data-finding-id="GHSA-hook"' in r.text


def test_review_required_candidate_still_shows_veto_reasons(client, wizard_db):
    scan = _cached_scan_dict(entries=[_entry("pkg", [_rf("GHSA-veto", 8)], tier="review_required")])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = open_wizard_select(client, "veto-reasons", scan)
    assert "candidate-row-reasons" in r.text
    assert "r" in r.text


def test_build_candidates_by_tier_propagates_deep_fields():
    entry = {
        "finding": _depth_finding(),
        "related_findings": [_depth_finding()],
        "candidate": {"package": "m", "from_version": "1", "to_version": "2", "candidate_id": "c1"},
        "verdict": {
            "tier": "auto_merge",
            "score": 1,
            "veto_signals": [],
            "reasons": [],
            "candidate_id": "c1",
        },
    }
    candidate = build_candidates_by_tier({"entries": [entry]})["auto_merge"][0]
    finding = candidate.findings[0]
    assert isinstance(finding, ResultsFindingView)
    assert finding.description_html is not None
    assert finding.fixed_range is not None
