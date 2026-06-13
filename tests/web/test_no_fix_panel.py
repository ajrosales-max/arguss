"""Tests for the no-fix panel on the results page."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from arguss.engine.skips import no_fix_reason_label
from arguss.web.results_context import (
    build_no_fix_panel,
    build_package_status_summary,
    build_results_context,
)
from arguss.web.url_scan import serialize_lockfile_deps
from tests.fixtures.scan_counts_helpers import attach_minimal_scan_counts
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict

_FIXTURE_LOCKFILE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "lockfiles" / "with-transitive.json"
)


def _no_fix_skip(*, package: str, version: str, advisory_id: str, title: str) -> dict[str, Any]:
    return {
        "kind": "no_fix",
        "advisory_id": advisory_id,
        "package": package,
        "current_version": version,
        "title": title,
        "description": "No patch available.",
        "reason": "no_fix_version_in_osv",
        "reason_label": no_fix_reason_label("no_fix_version_in_osv"),
    }


def _mixed_no_fix_scan(lockfile_path: Path) -> dict[str, Any]:
    deps = serialize_lockfile_deps(lockfile_path)
    deps.append({"package": "left-pad", "version": "1.3.0", "is_direct": False})
    chalk = _cached_entry(package="chalk", tier="auto_merge")
    chalk["candidate"]["from_version"] = "4.1.2"
    chalk["candidate"]["to_version"] = "4.1.3"
    skips = [
        _no_fix_skip(
            package="chalk", version="4.1.2", advisory_id="GHSA-chalk-mix", title="Chalk no fix"
        ),
        _no_fix_skip(
            package="color-convert",
            version="2.0.1",
            advisory_id="GHSA-color",
            title="Color convert no fix",
        ),
        _no_fix_skip(
            package="left-pad",
            version="1.3.0",
            advisory_id="GHSA-left",
            title="Left pad no fix",
        ),
    ]
    scan = _cached_scan_dict(entries=[chalk])
    scan["deps"] = deps
    scan["skipped_findings"] = skips
    scan["scan_meta"]["dep_counts"] = {
        "direct": sum(1 for d in deps if d.get("is_direct")),
        "transitive": sum(1 for d in deps if not d.get("is_direct")),
    }
    scan = attach_minimal_scan_counts(scan, total_findings=1 + len(skips))
    scan["scan_counts"]["findings_no_fix"] = len(skips)
    scan["scan_counts"]["package_status_no_fix"] = 2
    return scan


@pytest.fixture
def lockfile_path(tmp_path: Path) -> Path:
    dest = tmp_path / "package-lock.json"
    shutil.copy(_FIXTURE_LOCKFILE, dest)
    return dest


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def test_primary_group_count_equals_package_status_no_fix(lockfile_path: Path) -> None:
    scan = _mixed_no_fix_scan(lockfile_path)
    panel = build_no_fix_panel(scan)
    status = build_package_status_summary(scan)
    assert panel is not None
    assert panel.primary_package_count == 2
    assert status.no_fix_count == 2


def test_mixed_package_in_trailing_not_primary(lockfile_path: Path) -> None:
    scan = _mixed_no_fix_scan(lockfile_path)
    panel = build_no_fix_panel(scan)
    assert panel is not None
    primary_names = {g.package for g in panel.primary_groups}
    trailing_names = {g.package for g in panel.trailing_groups}
    assert "chalk" in trailing_names
    assert "chalk" not in primary_names
    assert "color-convert" in primary_names
    assert "left-pad" in primary_names


def test_total_rendered_findings_equals_findings_no_fix(
    client: TestClient, lockfile_path: Path
) -> None:
    scan = _mixed_no_fix_scan(lockfile_path)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/no-fix-panel-rows")
    assert response.status_code == 200
    panel_start = response.text.index('id="no-fix-panel"')
    panel_end = response.text.index("</section>", panel_start)
    panel_html = response.text[panel_start:panel_end]
    row_count = panel_html.count('class="critical-no-fix-row"')
    assert row_count == scan["scan_counts"]["findings_no_fix"]


def test_mixed_package_findings_in_package_card(client: TestClient, lockfile_path: Path) -> None:
    scan = _mixed_no_fix_scan(lockfile_path)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/no-fix-panel-card")
    assert response.status_code == 200
    assert 'id="package-row-chalk"' in response.text
    assert "Chalk no fix" in response.text
    assert "package-no-fix-findings" in response.text


def test_build_results_context_includes_no_fix_panel(lockfile_path: Path) -> None:
    scan = _mixed_no_fix_scan(lockfile_path)
    ctx = build_results_context(scan, "hash-mixed")
    assert ctx["no_fix_panel"] is not None
    assert ctx["no_fix_panel"].total_findings == 3


def test_render_gate_findings_no_fix_zero(lockfile_path: Path) -> None:
    scan = _mixed_no_fix_scan(lockfile_path)
    scan["scan_counts"]["findings_no_fix"] = 0
    assert build_no_fix_panel(scan) is None


def test_mixed_only_no_fix_renders_panel_and_status(lockfile_path: Path) -> None:
    deps = serialize_lockfile_deps(lockfile_path)
    chalk = _cached_entry(package="chalk", tier="auto_merge")
    chalk["candidate"]["from_version"] = "4.1.2"
    skip = _no_fix_skip(
        package="chalk", version="4.1.2", advisory_id="GHSA-chalk-mix", title="Chalk no fix"
    )
    scan = _cached_scan_dict(entries=[chalk])
    scan["deps"] = deps
    scan["skipped_findings"] = [skip]
    scan = attach_minimal_scan_counts(scan, total_findings=2)
    scan["scan_counts"]["findings_no_fix"] = 1
    scan["scan_counts"]["package_status_no_fix"] = 0
    scan["scan_counts"]["package_status_mixed_no_fix"] = 1

    panel = build_no_fix_panel(scan)
    status = build_package_status_summary(scan)
    assert panel is not None
    assert panel.primary_package_count == 0
    assert panel.mixed_package_count == 1
    assert len(panel.trailing_groups) == 1
    assert status.no_fix_count == 0
    assert status.mixed_no_fix_count == 1


def test_two_number_status_copy(client: TestClient, lockfile_path: Path) -> None:
    scan = _mixed_no_fix_scan(lockfile_path)
    scan["scan_counts"]["package_status_mixed_no_fix"] = 1
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/pkg-status-render")
    text = response.text
    assert "2 packages with no automated fix" in text
    assert "+1 more with unfixable findings alongside fixable ones" in text
    assert 'href="#no-fix-trailing"' in text


def test_render_gate_requires_scan_counts_findings_no_fix(lockfile_path: Path) -> None:
    scan = _mixed_no_fix_scan(lockfile_path)
    del scan["scan_counts"]["findings_no_fix"]
    assert build_no_fix_panel(scan) is None
