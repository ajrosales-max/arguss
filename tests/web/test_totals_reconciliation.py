"""Template and integration tests for scan_counts totals reconciliation."""

from __future__ import annotations

import re
from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.explanations.executive_summary as exec_mod
import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from arguss.core.serialization import finalize_scan_payload
from arguss.web.results_context import build_candidates_by_tier
from tests.engine import test_scan_counts as engine_fixtures
from tests.fixtures.scan_counts_helpers import attach_minimal_scan_counts
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict
from tests.test_executive_summary import _entry, _scan_counts_fixture_52_15_21, _scan_result

_TIER_TAB_COUNTS_RE = re.compile(r'tier-tab-count">(\d+)')


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def _finalize_simple_git_scan(tmp_path) -> dict[str, Any]:
    findings = tuple(
        engine_fixtures._finding(
            advisory_id=f"GHSA-sg-ui-{i}", package="simple-git", version="3.28.0"
        )
        for i in range(3)
    )
    report = engine_fixtures._report(
        entries=(engine_fixtures._entry(findings),),
        findings_snapshot=findings,
    )
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        '{"lockfileVersion":3,"packages":{"":{"name":"t","version":"1.0.0"},'
        '"node_modules/simple-git":{"version":"3.28.0"}}}'
    )
    payload = finalize_scan_payload(report, lockfile)
    payload["scan_meta"] = {
        "repo_display": "demo/simple-git",
        "ref": "HEAD",
        "mode": "A",
        "completed_at": "2026-05-18T12:00:00+00:00",
        "dep_counts": {"direct": 1, "transitive": 0},
    }
    payload["executive_summary"] = "Totals reconciliation test scan."
    return payload


def _minimatch_scan_dict() -> dict[str, Any]:
    def rf(aid: str, version: str) -> dict[str, Any]:
        return {
            "advisory_id": aid,
            "finding_id": f"fid-{aid}",
            "title": f"{aid}: test",
            "severity": "high",
            "dependency": {
                "name": "minimatch",
                "version": version,
                "path": ["root"],
                "direct": False,
            },
            "lens": "cve",
            "score": 1.0,
            "description": "d",
        }

    specs = [
        ("9.0.3", ["GHSA-mm-1"]),
        ("9.0.5", ["GHSA-mm-2a", "GHSA-mm-2b"]),
        ("9.0.7", ["GHSA-mm-3"]),
    ]
    entries: list[dict[str, Any]] = []
    candidate_records: list[dict[str, Any]] = []
    for version, aids in specs:
        related = [rf(a, version) for a in aids]
        cid = f"cand-minimatch-{version}"
        entries.append(
            {
                "finding": related[0],
                "related_findings": related,
                "candidate": {
                    "package": "minimatch",
                    "from_version": version,
                    "to_version": "9.9.9",
                    "candidate_id": cid,
                },
                "verdict": {
                    "score": 40,
                    "tier": "auto_merge",
                    "veto_signals": [],
                    "reasons": ["test"],
                    "candidate_id": cid,
                },
            }
        )
        candidate_records.append(
            {
                "candidate_id": cid,
                "package": "minimatch",
                "from_version": version,
                "to_version": "9.9.9",
                "tier": "auto_merge",
                "related_finding_ids": [f"fid-{a}" for a in aids],
                "aggregates": {"max_epss_score": None},
            }
        )
    scan = _cached_scan_dict(entries=entries)
    scan["scan_counts"] = {
        "total_findings": 4,
        "total_candidates": 3,
        "candidates_auto_merge": 3,
        "candidates_review_required": 0,
        "candidates_decline": 0,
        "candidates_unknown_tier": 0,
        "findings_no_fix": 0,
        "candidates": candidate_records,
        "package_rollups": [{"package": "minimatch", "finding_count": 4}],
    }
    scan["summary"].update(
        {
            "total_findings": 4,
            "total_candidates": 3,
            "auto_merge_count": 3,
        }
    )
    return scan


def test_assessment_package_badge_uses_rollup_finding_count(client: TestClient, tmp_path) -> None:
    scan = _finalize_simple_git_scan(tmp_path)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/simple-git-totals")
    assert response.status_code == status.HTTP_200_OK
    assert "simple-git" in response.text
    assert "3 findings" in response.text


def test_candidate_finding_counts_sum_to_scan_total_findings() -> None:
    scan = _minimatch_scan_dict()
    grouped = build_candidates_by_tier(scan)
    total = sum(
        candidate.finding_count for tier in grouped["tier_order"] for candidate in grouped[tier]
    )
    assert total == scan["scan_counts"]["total_findings"]


def test_tier_tab_counts_match_scan_counts(client: TestClient) -> None:
    scan = _cached_scan_dict(
        entries=[
            _cached_entry(tier="auto_merge"),
            _cached_entry(package="pkg-b", tier="review_required"),
            _cached_entry(package="pkg-c", tier="decline"),
        ],
    )
    scan["scan_counts"] = {
        "total_candidates": 3,
        "candidates_auto_merge": 1,
        "candidates_review_required": 1,
        "candidates_decline": 1,
        "findings_no_fix": 0,
    }
    scan["summary"].update(
        {
            "total_candidates": 99,
            "auto_merge_count": 99,
            "review_required_count": 99,
            "decline_count": 99,
        }
    )
    scan = attach_minimal_scan_counts(scan)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/tier-tabs")
    assert response.status_code == status.HTTP_200_OK
    counts = [int(m) for m in _TIER_TAB_COUNTS_RE.findall(response.text)]
    assert counts[:4] == [3, 1, 1, 1]


def test_exec_summary_claude_input_includes_count_glossary_terms() -> None:
    scan = _scan_result(
        entries=[_entry(package="lodash", score=40), _entry(package="axios", score=50)],
    )
    scan["scan_counts"] = _scan_counts_fixture_52_15_21()
    claude_input = exec_mod.build_claude_input(scan)
    glossary = claude_input["count_glossary"]
    assert (
        glossary["canonical_headline"]
        == "52 findings across 15 packages, consolidated into 21 upgrade candidates."
    )
    labels = {term["label"] for term in glossary["terms"]}
    assert "findings" in labels
    assert all("definition" in term for term in glossary["terms"])


def test_exec_summary_system_prompt_mentions_count_glossary() -> None:
    assert "count_glossary" in exec_mod._SYSTEM_PROMPT
    assert "canonical_headline" in exec_mod._SYSTEM_PROMPT


def test_mode_c_assessment_page_renders_scan_plus_action_label(client: TestClient) -> None:
    scan = _cached_scan_dict(entries=[_cached_entry(package="axios")], mode="C")
    scan["scan_counts"] = {"total_findings": 1, "total_candidates": 1}
    scan = attach_minimal_scan_counts(scan)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/mode-c-totals")
    assert response.status_code == status.HTTP_200_OK
    assert "Scan + Action" in response.text
    assert 'data-filter="all"' in response.text or "tier-filter" in response.text


def _multi_install_path_scan() -> dict[str, Any]:
    cid = "cand-lodash-multi"
    related = [
        {
            "advisory_id": "GHSA-same-adv",
            "finding_id": "fid-path-a",
            "title": "GHSA-same-adv: lodash issue",
            "severity": "high",
            "dependency": {
                "name": "lodash",
                "version": "4.17.20",
                "path": ["root", "pkg-a"],
                "direct": False,
            },
            "lens": "cve",
            "score": 1.0,
            "description": "d",
        },
        {
            "advisory_id": "GHSA-same-adv",
            "finding_id": "fid-path-b",
            "title": "GHSA-same-adv: lodash issue",
            "severity": "high",
            "dependency": {
                "name": "lodash",
                "version": "4.17.20",
                "path": ["root", "pkg-b"],
                "direct": False,
            },
            "lens": "cve",
            "score": 1.0,
            "description": "d",
        },
    ]
    scan = _cached_scan_dict(
        entries=[
            {
                "finding": related[0],
                "related_findings": related,
                "candidate": {
                    "package": "lodash",
                    "from_version": "4.17.20",
                    "to_version": "4.17.21",
                    "candidate_id": cid,
                },
                "verdict": {
                    "score": 40,
                    "tier": "auto_merge",
                    "veto_signals": [],
                    "reasons": ["test"],
                    "candidate_id": cid,
                },
            }
        ]
    )
    scan["scan_counts"] = {
        "total_findings": 2,
        "total_candidates": 1,
        "candidates_auto_merge": 1,
        "candidates_review_required": 0,
        "candidates_decline": 0,
        "candidates_unknown_tier": 0,
        "findings_no_fix": 0,
        "package_rollups": [{"package": "lodash", "finding_count": 2}],
    }
    scan["summary"].update({"total_findings": 2, "total_candidates": 1, "auto_merge_count": 1})
    return scan


def test_multi_install_path_renders_affects_n_install_paths(client: TestClient) -> None:
    scan = _multi_install_path_scan()
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/multi-install-path")
    assert response.status_code == status.HTTP_200_OK
    assert "2 findings" in response.text
    assert response.text.count("package-advisory-card") == 1
    assert "Affects 2 install paths" in response.text


def test_finding_card_renders_epss_na_not_zero_percent(client: TestClient) -> None:
    cid = "cand-epss-na"
    entry = {
        "finding": {
            "advisory_id": "GHSA-epss-na",
            "severity": "high",
            "is_kev": False,
            "epss_score": None,
            "epss_percentile": None,
            "dependency": {
                "name": "axios",
                "version": "1.0.0",
                "path": ["root", "axios"],
                "direct": False,
            },
            "title": "GHSA-epss-na: test",
            "remediation": "Upgrade",
            "source_url": "https://github.com/advisories/GHSA-epss-na",
        },
        "related_findings": [],
        "candidate": {
            "package": "axios",
            "from_version": "1.0.0",
            "to_version": "1.0.1",
            "candidate_id": cid,
        },
        "verdict": {
            "score": 40,
            "tier": "auto_merge",
            "veto_signals": [],
            "reasons": ["test"],
            "candidate_id": cid,
        },
    }
    scan = _cached_scan_dict(entries=[entry])
    scan["scan_counts"] = {"total_findings": 1, "total_candidates": 1, "findings_no_fix": 0}
    scan = attach_minimal_scan_counts(scan)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/epss-na-card")
    assert response.status_code == status.HTTP_200_OK
    assert "EPSS: n/a" in response.text
    assert "finding-epss-na" in response.text
    assert "0.0%" not in response.text
    assert "0th percentile" not in response.text
    assert "EPSS 0.0% probability" not in response.text


def test_tier_tab_includes_no_fix_divider_and_count(client: TestClient) -> None:
    scan = _cached_scan_dict(entries=[_cached_entry(tier="auto_merge")])
    scan["scan_counts"] = {
        "total_candidates": 1,
        "candidates_auto_merge": 1,
        "candidates_review_required": 0,
        "candidates_decline": 0,
        "findings_no_fix": 2,
    }
    scan = attach_minimal_scan_counts(scan)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/no-fix-tier-tab")
    assert response.status_code == status.HTTP_200_OK
    assert "tier-filter-no-fix-divider" in response.text
    assert "No fix available · 2 findings" in response.text


def test_select_row_finding_toggle_uses_finding_count(client: TestClient, wizard_db) -> None:
    from tests.web.conftest import open_wizard_select

    scan = _minimatch_scan_dict()
    two_finding_record = next(
        c for c in scan["scan_counts"]["candidates"] if len(c["related_finding_ids"]) == 2
    )
    expected = len(two_finding_record["related_finding_ids"])
    scan = attach_minimal_scan_counts(scan)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = open_wizard_select(client, "minimatch-toggle", scan, wizard_db=wizard_db)
    assert response.status_code == status.HTTP_200_OK
    assert f"▸ {expected} findings" in response.text
