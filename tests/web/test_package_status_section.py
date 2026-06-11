"""Tests for the package status section on the results page."""

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
    PackageStatusEntry,
    build_package_status_summary,
    build_results_context,
)
from arguss.web.url_scan import serialize_lockfile_deps
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict

_FIXTURE_LOCKFILE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "lockfiles" / "with-transitive.json"
)


@pytest.fixture
def lockfile_path(tmp_path: Path) -> Path:
    dest = tmp_path / "package-lock.json"
    shutil.copy(_FIXTURE_LOCKFILE, dest)
    return dest


def _scan_with_lockfile(
    lockfile_path: Path | None = None,
    *,
    entries: list[dict[str, Any]] | None = None,
    skipped_findings: list[dict[str, Any]] | None = None,
    summary_overrides: dict[str, Any] | None = None,
    deps: list[dict[str, Any]] | None = None,
    dep_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    scan = _cached_scan_dict(entries=entries or [])
    if lockfile_path is not None:
        scan["deps"] = deps if deps is not None else serialize_lockfile_deps(lockfile_path)
        counts = (
            dep_counts
            if dep_counts is not None
            else {
                "direct": sum(1 for d in scan["deps"] if d.get("is_direct")),
                "transitive": sum(1 for d in scan["deps"] if not d.get("is_direct")),
            }
        )
        scan["scan_meta"]["dep_counts"] = counts
    elif deps is not None:
        scan["deps"] = deps
    if dep_counts is not None:
        scan["scan_meta"]["dep_counts"] = dep_counts
    if skipped_findings is not None:
        scan["skipped_findings"] = skipped_findings
    if summary_overrides:
        scan["summary"].update(summary_overrides)
    return scan


def _chalk_entry(*, tier: str = "auto_merge") -> dict[str, Any]:
    entry = _cached_entry(package="chalk", tier=tier)
    entry["candidate"]["from_version"] = "4.1.2"
    entry["candidate"]["to_version"] = "4.1.3"
    return entry


def _ansi_entry(*, tier: str = "review_required") -> dict[str, Any]:
    entry = _cached_entry(package="ansi-styles", tier=tier)
    entry["candidate"]["from_version"] = "4.3.0"
    entry["candidate"]["to_version"] = "4.3.1"
    return entry


def test_clean_excludes_packages_with_candidate_findings(lockfile_path: Path) -> None:
    cached = _scan_with_lockfile(lockfile_path, entries=[_chalk_entry()])
    status = build_package_status_summary(cached)
    clean_names = {entry.package for entry in status.clean}
    assert "chalk" not in clean_names
    assert "ansi-styles" in clean_names
    assert len(status.clean) == 5


def test_clean_excludes_packages_with_no_fix_skips(lockfile_path: Path) -> None:
    skip = {
        "kind": "no_fix",
        "advisory_id": "GHSA-nf",
        "package": "color-convert",
        "current_version": "2.0.1",
        "title": "Unpatched",
        "description": "d",
        "reason": "no_fix_version_in_osv",
        "reason_label": no_fix_reason_label("no_fix_version_in_osv"),
    }
    cached = _scan_with_lockfile(lockfile_path, skipped_findings=[skip])
    status = build_package_status_summary(cached)
    assert all(entry.package != "color-convert" for entry in status.clean)
    assert status.no_fix_count == 1


def test_total_sourced_from_dep_counts_not_lockfile_reparse(lockfile_path: Path) -> None:
    cached = _scan_with_lockfile(lockfile_path)
    cached.pop("lockfile_path", None)
    status = build_package_status_summary(cached)
    assert status.total == 6


def test_total_correct_when_lockfile_path_absent() -> None:
    cached = _scan_with_lockfile(
        None,
        deps=[
            {"package": "chalk", "version": "4.1.2", "is_direct": True},
            {"package": "ansi-styles", "version": "4.3.0", "is_direct": False},
        ],
        dep_counts={"direct": 1, "transitive": 1},
    )
    assert build_package_status_summary(cached).total == 2


def test_clean_derived_from_cached_deps(lockfile_path: Path) -> None:
    cached = _scan_with_lockfile(lockfile_path, entries=[_chalk_entry()])
    status = build_package_status_summary(cached)
    assert len(status.clean) == 5
    assert all(entry.package for entry in status.clean)


def test_backward_compat_missing_deps_field_yields_empty_clean() -> None:
    cached = _scan_with_lockfile(
        None,
        dep_counts={"direct": 1, "transitive": 5},
    )
    status = build_package_status_summary(cached)
    assert status.total == 6
    assert status.clean == ()
    assert status.integrity_ok is False


def test_integrity_ok_when_categories_sum_correctly(lockfile_path: Path) -> None:
    cached = _scan_with_lockfile(
        lockfile_path,
        entries=[_chalk_entry(tier="auto_merge"), _ansi_entry(tier="review_required")],
        summary_overrides={
            "auto_merge_count": 1,
            "review_required_count": 1,
            "decline_count": 0,
        },
    )
    status = build_package_status_summary(cached)
    assert status.integrity_ok is True
    assert status.accounted_total == status.total == 6


def test_integrity_ok_when_accounted_matches_total(lockfile_path: Path) -> None:
    cached = _scan_with_lockfile(
        lockfile_path,
        entries=[_chalk_entry(tier="auto_merge")],
        summary_overrides={
            "auto_merge_count": 1,
            "review_required_count": 0,
            "decline_count": 0,
        },
    )
    status = build_package_status_summary(cached)
    assert status.integrity_ok is True
    assert status.accounted_total == status.total == 6


def test_integrity_flagged_when_summary_counts_drift(lockfile_path: Path) -> None:
    cached = _scan_with_lockfile(
        lockfile_path,
        entries=[_chalk_entry(tier="auto_merge")],
        summary_overrides={
            "auto_merge_count": 2,
            "review_required_count": 0,
            "decline_count": 0,
        },
    )
    status = build_package_status_summary(cached)
    assert status.integrity_ok is False
    assert status.accounted_total == 7
    assert status.total == 6


def test_clean_sorted_direct_first_then_alphabetically(lockfile_path: Path) -> None:
    cached = _scan_with_lockfile(lockfile_path, entries=[_ansi_entry()])
    status = build_package_status_summary(cached)
    assert status.clean[0] == PackageStatusEntry(package="chalk", version="4.1.2", is_direct=True)
    rest_names = [entry.package for entry in status.clean[1:]]
    assert rest_names == sorted(rest_names, key=str.lower)


def test_build_results_context_includes_package_status(lockfile_path: Path) -> None:
    cached = _scan_with_lockfile(lockfile_path)
    ctx = build_results_context(cached, "hash-demo")
    assert "package_status" in ctx
    assert ctx["package_status"].total == 6


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def test_results_page_renders_package_status_section(
    client: TestClient, lockfile_path: Path
) -> None:
    scan = _scan_with_lockfile(
        lockfile_path,
        entries=[_chalk_entry(tier="auto_merge"), _ansi_entry(tier="review_required")],
        summary_overrides={
            "auto_merge_count": 1,
            "review_required_count": 1,
            "decline_count": 0,
        },
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/pkg-status-render")
    assert response.status_code == 200
    text = response.text
    assert 'class="package-status-section"' in text
    assert "Package status" in text
    assert 'href="/select"' in text
    assert 'id="clean-packages"' in text
    assert "hidden" in text


def test_results_page_shows_no_fix_anchor(client: TestClient, lockfile_path: Path) -> None:
    skip = {
        "kind": "no_fix",
        "advisory_id": "GHSA-nf",
        "package": "chalk",
        "current_version": "4.1.2",
        "title": "Unpatched chalk",
        "description": "d",
        "reason": "no_fix_version_in_osv",
        "reason_label": no_fix_reason_label("no_fix_version_in_osv"),
    }
    scan = _scan_with_lockfile(
        lockfile_path,
        skipped_findings=[skip],
        summary_overrides={"auto_merge_count": 0, "review_required_count": 0, "decline_count": 0},
    )
    scan["summary"]["total_findings"] = 1
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/pkg-status-nofix")
    text = response.text
    assert 'id="critical-no-fix-list"' in text
    assert 'href="#critical-no-fix-list"' in text


def test_integrity_warning_renders_when_counts_mismatch(
    client: TestClient, lockfile_path: Path
) -> None:
    scan = _scan_with_lockfile(
        lockfile_path,
        entries=[_chalk_entry()],
        summary_overrides={"auto_merge_count": 3},
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/pkg-status-integrity")
    assert "package-status-integrity-warning" in response.text
    assert "Count mismatch" in response.text


def test_banner_includes_clean_package_count(client: TestClient, lockfile_path: Path) -> None:
    scan = _scan_with_lockfile(lockfile_path, entries=[_chalk_entry()])
    scan["summary"]["total_findings"] = 1
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/pkg-status-banner")
    text = response.text
    assert "5 packages clean" in text
    assert "6 packages" in text
    assert "Candidates:" in text
    assert "tally-chips" not in text


def test_scan_response_includes_deps_array(lockfile_path: Path) -> None:
    deps = serialize_lockfile_deps(lockfile_path)
    assert len(deps) == 6
    assert all("package" in entry and "version" in entry for entry in deps)


def test_deps_array_entry_has_name_version_is_direct(lockfile_path: Path) -> None:
    chalk = next(
        entry for entry in serialize_lockfile_deps(lockfile_path) if entry["package"] == "chalk"
    )
    assert chalk == {
        "package": "chalk",
        "version": "4.1.2",
        "is_direct": True,
    }
