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
from tests.fixtures.scan_counts_helpers import attach_minimal_scan_counts
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
    if skipped_findings is not None:
        total = len(scan.get("entries") or []) + len(skipped_findings)
        scan = attach_minimal_scan_counts(scan, total_findings=total)
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


def _entry_with_tier(
    package: str,
    version: str,
    *,
    tier: str | None = "auto_merge",
) -> dict[str, Any]:
    entry = _cached_entry(package=package, tier=tier or "auto_merge")
    entry["candidate"]["from_version"] = version
    entry["finding"]["dependency"] = {
        "name": package,
        "version": version,
        "path": ["root", package],
        "direct": False,
    }
    entry["verdict"] = {**entry["verdict"], "tier": tier}
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


def test_total_uses_unique_name_version_not_install_path_count(lockfile_path: Path) -> None:
    deps = serialize_lockfile_deps(lockfile_path)
    cached = _scan_with_lockfile(
        lockfile_path,
        deps=deps + [dict(deps[0])],
        dep_counts={"direct": 99, "transitive": 99},
    )
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


def test_total_dedupes_when_deps_array_has_duplicates(lockfile_path: Path) -> None:
    deps = serialize_lockfile_deps(lockfile_path)
    duplicated = deps + [dict(deps[0]), dict(deps[1])]
    cached = _scan_with_lockfile(lockfile_path, deps=duplicated)
    assert build_package_status_summary(cached).total == 6


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
    assert status.total == 0
    assert status.clean == ()
    assert status.integrity_ok is True


def test_integrity_passes_on_healthy_scan(lockfile_path: Path) -> None:
    cached = _scan_with_lockfile(
        lockfile_path,
        entries=[_chalk_entry(tier="auto_merge"), _ansi_entry(tier="review_required")],
    )
    status = build_package_status_summary(cached)
    assert status.integrity_ok is True
    assert status.accounted_total == status.total == 6


def test_integrity_ok_when_accounted_matches_total(lockfile_path: Path) -> None:
    cached = _scan_with_lockfile(
        lockfile_path,
        entries=[_chalk_entry(tier="auto_merge")],
    )
    status = build_package_status_summary(cached)
    assert status.integrity_ok is True
    assert status.accounted_total == status.total == 6


def test_integrity_flagged_when_entry_missing_tier(lockfile_path: Path) -> None:
    entry = _chalk_entry(tier="auto_merge")
    entry["verdict"] = {**entry["verdict"], "tier": None}
    cached = _scan_with_lockfile(lockfile_path, entries=[entry])
    status = build_package_status_summary(cached)
    assert status.integrity_ok is False
    assert status.accounted_total == 5
    assert status.total == 6


def test_clean_dedupes_direct_flag_when_duplicate_dep_rows(lockfile_path: Path) -> None:
    deps = serialize_lockfile_deps(lockfile_path)
    chalk = next(d for d in deps if d["package"] == "chalk")
    transitive_chalk = {**chalk, "is_direct": False}
    direct_chalk = {**chalk, "is_direct": True}
    cached = _scan_with_lockfile(lockfile_path, deps=[transitive_chalk, direct_chalk])
    status = build_package_status_summary(cached)
    chalk_clean = next((e for e in status.clean if e.package == "chalk"), None)
    assert chalk_clean is not None
    assert chalk_clean.is_direct is True


def test_categories_count_unique_packages_not_candidates(lockfile_path: Path) -> None:
    cached = _scan_with_lockfile(
        lockfile_path,
        entries=[
            _chalk_entry(tier="auto_merge"),
            _entry_with_tier("chalk", "4.1.2", tier="auto_merge"),
        ],
        summary_overrides={
            "auto_merge_count": 2,
            "review_required_count": 0,
            "decline_count": 0,
        },
    )
    status = build_package_status_summary(cached)
    assert status.auto_merge_count == 1
    assert cached["summary"]["auto_merge_count"] == 2


def test_package_with_multiple_findings_in_same_tier_counts_once(lockfile_path: Path) -> None:
    cached = _scan_with_lockfile(
        lockfile_path,
        entries=[
            _chalk_entry(tier="review_required"),
            _entry_with_tier("chalk", "4.1.2", tier="review_required"),
        ],
    )
    status = build_package_status_summary(cached)
    assert status.review_required_count == 1
    assert status.auto_merge_count == 0


def test_package_with_findings_across_tiers_buckets_to_highest_severity(
    lockfile_path: Path,
) -> None:
    cached = _scan_with_lockfile(
        lockfile_path,
        entries=[
            _chalk_entry(tier="auto_merge"),
            _entry_with_tier("chalk", "4.1.2", tier="decline"),
        ],
    )
    status = build_package_status_summary(cached)
    assert status.decline_count == 1
    assert status.auto_merge_count == 0
    assert status.review_required_count == 0


def test_package_with_no_fix_skip_overrides_candidate_tier(lockfile_path: Path) -> None:
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
    cached = _scan_with_lockfile(
        lockfile_path,
        entries=[_chalk_entry(tier="auto_merge")],
        skipped_findings=[skip],
    )
    status = build_package_status_summary(cached)
    assert status.no_fix_count == 0
    assert status.mixed_no_fix_count == 0
    assert status.auto_merge_count == 1


def _realistic_axios_cached_scan() -> dict[str, Any]:
    deps = [
        {"package": "axios", "version": "1.6.0", "is_direct": True},
        {"package": "follow-redirects", "version": "1.15.4", "is_direct": False},
        {"package": "form-data", "version": "4.0.0", "is_direct": False},
        {"package": "proxy-from-env", "version": "1.1.0", "is_direct": False},
    ]
    entries = [
        _entry_with_tier("axios", "1.6.0", tier="review_required"),
        _entry_with_tier("follow-redirects", "1.15.4", tier="auto_merge"),
        _entry_with_tier("follow-redirects", "1.15.4", tier="decline"),
    ]
    return _scan_with_lockfile(
        None,
        deps=deps,
        dep_counts={"direct": 1, "transitive": 3},
        entries=entries,
        summary_overrides={
            "auto_merge_count": 1,
            "review_required_count": 1,
            "decline_count": 1,
            "total_findings": 3,
        },
    )


def test_integrity_check_passes_with_realistic_axios_fixture() -> None:
    cached = _realistic_axios_cached_scan()
    status = build_package_status_summary(cached)
    assert status.total == 4
    assert status.review_required_count == 1
    assert status.decline_count == 1
    assert status.auto_merge_count == 0
    assert status.no_fix_count == 0
    assert len(status.clean) == 2
    assert status.integrity_ok is True
    assert status.accounted_total == 4


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
    assert "status-tier-link" in text
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
    assert 'id="no-fix-primary"' in text
    assert 'href="#no-fix-primary"' in text and 'data-tier-filter="skipped"' in text


def test_integrity_warning_renders_when_counts_mismatch(
    client: TestClient, lockfile_path: Path
) -> None:
    entry = _chalk_entry()
    entry["verdict"] = {**entry["verdict"], "tier": None}
    scan = _scan_with_lockfile(lockfile_path, entries=[entry])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/pkg-status-integrity")
    assert "package-status-integrity-warning" in response.text
    assert "Count mismatch" in response.text


def test_banner_includes_clean_package_count(client: TestClient, lockfile_path: Path) -> None:
    scan = _scan_with_lockfile(
        lockfile_path,
        entries=[_chalk_entry()],
        summary_overrides={"auto_merge_count": 1, "review_required_count": 0, "decline_count": 0},
    )
    scan["summary"]["total_findings"] = 1
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/pkg-status-banner")
    text = response.text
    assert "5 packages clean" in text
    assert "6 packages" in text
    assert "Candidates:" in text
    assert "1 auto-merge" in text
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
