"""Template tests for dual-select tier defaults and merge authorization notice."""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from tests.fixtures.scan_counts_helpers import attach_minimal_scan_counts
from tests.web.conftest import open_wizard_select

_FIXED_TIME = "2026-05-18T12:00:00+00:00"


def _cached_entry(
    *,
    package: str = "path-to-regexp",
    tier: str = "review_required",
    veto_signals: tuple[str, ...] = (),
    reasons: tuple[str, ...] = ("test reason",),
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
            "reasons": list(reasons),
            "candidate_id": cid,
        },
    }


def _cached_scan_dict(*, entries: list[dict[str, Any]], mode: str = "A") -> dict[str, Any]:
    payload = {
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
    return attach_minimal_scan_counts(payload)


def _row_snippet(html: str, candidate_id: str) -> str:
    marker = f'data-candidate-id="{candidate_id}"'
    pos = html.index(marker)
    start = html.rfind('<li class="candidate-selection-row', 0, pos)
    assert start != -1
    depth = 0
    i = start
    while i < len(html):
        if html.startswith("<li", i):
            depth += 1
            i += 3
            continue
        if html.startswith("</li>", i):
            depth -= 1
            if depth == 0:
                return html[start : i + 5]
            i += 5
            continue
        i += 1
    raise AssertionError(f"row end not found for {candidate_id}")


def _input_snippet(row: str, css_class: str) -> str:
    idx = row.index(f'class="{css_class}"')
    end = row.find(">", idx)
    assert end != -1
    return row[idx : end + 1]


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def test_auto_merge_tier_both_checkboxes_checked_and_green_row(
    client: TestClient, wizard_db
) -> None:
    scan = _cached_scan_dict(entries=[_cached_entry(package="safe-pkg", tier="auto_merge")])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = open_wizard_select(client, "auto-merge-dual", scan)

    text = response.text
    assert "candidate-selection-row-auto_merge" in text
    row = _row_snippet(text, "cand-safe-pkg-001")
    assert "checked" in _input_snippet(row, "candidate-checkbox")
    assert "checked" in _input_snippet(row, "candidate-auto-merge-checkbox")


def test_review_required_tier_unchecked_with_merge_notice_markup(
    client: TestClient, wizard_db
) -> None:
    scan = _cached_scan_dict(
        entries=[
            _cached_entry(
                package="review-pkg",
                tier="review_required",
                veto_signals=("pipeline.test_reality", "trust.low_score"),
                reasons=("CI reality veto", "Low trust subscore"),
            )
        ]
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = open_wizard_select(client, "review-merge-notice", scan)

    text = response.text
    row = _row_snippet(text, "cand-review-pkg-001")
    assert "checked" not in _input_snippet(row, "candidate-checkbox")
    assert "checked" not in _input_snippet(row, "candidate-auto-merge-checkbox")
    assert 'class="merge-authorization-notice" hidden' in row
    assert "You are authorizing a merge the engine flagged for review:" in row
    assert "pipeline.test_reality" in row
    assert "trust.low_score" in row
    assert "CI reality veto" in row
    assert "Low trust subscore" in row


def test_decline_tier_no_merge_checkbox_even_with_override(
    client: TestClient, wizard_db, allow_decline_override
) -> None:
    allow_decline_override(True)
    scan = _cached_scan_dict(entries=[_cached_entry(package="declined-pkg", tier="decline")])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = open_wizard_select(client, "decline-no-merge", scan)

    row = _row_snippet(response.text, "cand-declined-pkg-001")
    assert 'class="candidate-checkbox"' in row
    assert "candidate-auto-merge-checkbox" not in row


def test_select_all_engine_merges_button_present(client: TestClient, wizard_db) -> None:
    scan = _cached_scan_dict(entries=[_cached_entry(package="safe-pkg", tier="auto_merge")])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = open_wizard_select(client, "engine-merge-btn", scan)

    text = response.text
    assert 'id="candidate-select-all-engine-merges"' in text
    assert "Select all engine-approved merges" in text
    assert 'id="candidate-auto-merge-only"' not in text
    assert "Auto-merge only" not in text
