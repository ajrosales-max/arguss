"""Tests for candidate findings drill-down on the remediation plan page."""

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
    build_results_context,
)
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict
from tests.web.conftest import open_wizard_select


def test_candidate_view_carries_findings():
    e = {
        "finding": {
            "advisory_id": "GHSA-a",
            "title": "t",
            "cvss_score": 9.0,
            "severity": "high",
            "dependency": {"name": "p", "version": "1"},
            "lens": "cve",
            "score": 1,
            "description": "d",
        },
        "related_findings": [
            {
                "advisory_id": "GHSA-a",
                "title": "GHSA-a: x",
                "cvss_score": 9.0,
                "severity": "high",
                "dependency": {"name": "p", "version": "1"},
                "lens": "cve",
                "score": 1,
                "description": "d",
            },
            {
                "advisory_id": "GHSA-b",
                "title": "GHSA-b: y",
                "cvss_score": 7.0,
                "severity": "high",
                "dependency": {"name": "p", "version": "1"},
                "lens": "cve",
                "score": 1,
                "description": "d",
            },
        ],
        "candidate": {"package": "m", "from_version": "1", "to_version": "2", "candidate_id": "c1"},
        "verdict": {
            "tier": "auto_merge",
            "score": 1,
            "veto_signals": [],
            "reasons": [],
            "candidate_id": "c1",
        },
    }
    c = build_candidates_by_tier({"entries": [e]})["auto_merge"][0]
    assert len(c.findings) == 2


def test_candidate_findings_sorted_by_cvss_descending():
    def f(i, cvss):
        return {
            "advisory_id": i,
            "title": f"{i}: t",
            "cvss_score": cvss,
            "severity": "high",
            "dependency": {"name": "p", "version": "1"},
            "lens": "cve",
            "score": 1,
            "description": "d",
        }

    related = [f("GHSA-low", 3.0), f("GHSA-high", 9.5), f("GHSA-mid", 6.0)]
    e = {
        "finding": related[0],
        "related_findings": related,
        "candidate": {"package": "m", "from_version": "1", "to_version": "2", "candidate_id": "c"},
        "verdict": {
            "tier": "auto_merge",
            "score": 1,
            "veto_signals": [],
            "reasons": [],
            "candidate_id": "c",
        },
    }
    ids = [
        x.advisory_id for x in build_candidates_by_tier({"entries": [e]})["auto_merge"][0].findings
    ]
    assert ids == ["GHSA-high", "GHSA-mid", "GHSA-low"]


def test_consolidated_candidate_findings_sum_to_total():
    def f(aid):
        return {
            "advisory_id": aid,
            "title": f"{aid}: t",
            "cvss_score": 5.0,
            "severity": "high",
            "dependency": {"name": "p", "version": "1"},
            "lens": "cve",
            "score": 1,
            "description": "d",
        }

    def entry(pkg, aids):
        related = [f(a) for a in aids]
        return {
            "finding": related[0],
            "related_findings": related,
            "candidate": {
                "package": pkg,
                "from_version": "1",
                "to_version": "2",
                "candidate_id": pkg,
            },
            "verdict": {
                "tier": "auto_merge",
                "score": 1,
                "veto_signals": [],
                "reasons": [],
                "candidate_id": pkg,
            },
        }

    grouped = build_candidates_by_tier({"entries": [entry("m", ["a", "b"]), entry("q", ["c"])]})
    assert sum(len(c.findings) for t in grouped["tier_order"] for c in grouped[t]) == 3


def test_results_header_shows_scan_not_mode_a_context():
    ctx = build_results_context(
        {
            "entries": [],
            "project_scores": {},
            "summary": {
                "total_findings": 0,
                "auto_merge_count": 0,
                "review_required_count": 0,
                "decline_count": 0,
            },
            "skipped_findings": [],
            "scan_meta": {"mode": "A"},
        },
        "h",
    )
    assert ctx["scan"]["mode_display"] == "Scan"


@pytest.fixture
def client():
    return TestClient(api_app)


def _rf(aid, cvss):
    return {
        "advisory_id": aid,
        "title": f"{aid}: t",
        "cvss_score": cvss,
        "severity": "high",
        "source_url": f"https://osv.dev/vulnerability/{aid}",
        "dependency": {"name": "p", "version": "1", "path": ["r"], "direct": False},
        "lens": "cve",
        "score": 1,
        "description": "d",
        "fixed_versions": ["2.0.0"],
    }


def _entry(pkg, related, tier="auto_merge"):
    cid = f"cand-{pkg}-001"
    return {
        "finding": related[0],
        "related_findings": related,
        "candidate": {"package": pkg, "from_version": "1", "to_version": "2", "candidate_id": cid},
        "verdict": {
            "score": 40,
            "tier": tier,
            "veto_signals": [],
            "reasons": ["r"],
            "candidate_id": cid,
        },
    }


def test_multi_finding_candidate_renders_expand_toggle(client, wizard_db):
    scan = _cached_scan_dict(entries=[_entry("minimatch", [_rf("GHSA-a", 9), _rf("GHSA-b", 7)])])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = open_wizard_select(client, "multi-findings", scan)
    assert "findings-toggle" in r.text


def test_single_finding_candidate_has_toggle(client, wizard_db):
    scan = _cached_scan_dict(entries=[_entry("left-pad", [_rf("GHSA-one", 5)])])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = open_wizard_select(client, "single-finding", scan)
    assert 'class="findings-toggle btn-text"' in r.text
    assert "▸ 1 finding" in r.text


def test_findings_panel_hidden_by_default(client, wizard_db):
    scan = _cached_scan_dict(entries=[_entry("qs", [_rf("GHSA-x", 8), _rf("GHSA-y", 6)])])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = open_wizard_select(client, "hidden-panel", scan)
    i = r.text.index("candidate-findings")
    assert " hidden" in r.text[i : i + 80]


def test_checkbox_independent_of_findings_panel(client, wizard_db):
    scan = _cached_scan_dict(entries=[_entry("lodash", [_rf("GHSA-1", 9), _rf("GHSA-2", 8)])])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = open_wizard_select(client, "checkbox-independent", scan)
    t = r.text
    assert (
        t.index("candidate-checkbox") < t.index("findings-toggle") < t.index("candidate-findings")
    )


def test_results_header_shows_scan_not_mode_a(client):
    scan = _cached_scan_dict(entries=[_cached_entry(package="pkg", tier="auto_merge")])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.get("/assessment/scan-label")
    assert "Scan · Completed" in r.text and "Mode A" not in r.text


def test_results_headline_links_findings_to_candidates(client):
    scan = _cached_scan_dict(
        entries=[_entry("a", [_rf("GHSA-a", 9), _rf("GHSA-b", 7)]), _entry("b", [_rf("GHSA-c", 6)])]
    )
    scan["summary"]["total_findings"] = 3
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        r = client.get("/assessment/headline")
    assert (
        "tally-consolidation" in r.text
        and "3 findings" in r.text
        and "packages clean" in r.text
        and "Candidates:" in r.text
    )


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
    assert "Long advisory narrative." in r.text


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
