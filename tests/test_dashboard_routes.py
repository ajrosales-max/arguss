"""Tests for HTML dashboard routes."""

from __future__ import annotations

from dataclasses import fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from arguss.core.models import (
    Dependency,
    Finding,
    FixCandidate,
    FixConfidence,
    FixKind,
    FixTier,
    ProjectScores,
)
from arguss.core.serialization import proposal_report_with_actions_payload
from arguss.engine.fix_confidence import ENGINE_VERSION
from arguss.engine.propose import ProposalEntry, ProposalReport, ProposalSummary
from arguss.web.github_action import ActionResult
from arguss.web.github_fetch import GitHubFetchError, RepoInputs
from arguss.web.mode_c_workflow import ScanWithActionResult
from tests.fixtures.scan_counts_helpers import attach_minimal_scan_counts

_EXPRESS_URL = "https://github.com/expressjs/express"
_TEST_PAT = "ghp_test_pat_for_unit_tests_only_not_real"

_DEFAULT_PROJECT_SCORES = ProjectScores(
    prs=62,
    vulnerability_subscore=70,
    trust_subscore=50,
    pipeline_subscore=40,
    test_reality="vetoed",
)
_FIXED_TIME = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)
_FIXTURES = Path(__file__).parent / "fixtures" / "lockfiles"


def _stub_attach_executive_summary(payload: dict[str, Any]) -> dict[str, Any]:
    return {**payload, "executive_summary": "Test executive summary."}


def _cached_entry(
    *,
    package: str = "path-to-regexp",
    tier: str = "review_required",
    veto_signals: tuple[str, ...] = (),
    is_kev: bool = False,
    epss_score: float = 0.21,
) -> dict[str, Any]:
    return {
        "finding": {
            "severity": "high",
            "is_kev": is_kev,
            "dependency": {
                "path": ["root", "express", package],
                "direct": False,
                "version": "1.0.0",
            },
            "title": "Test advisory",
            "remediation": "Upgrade package",
            "source_url": "https://github.com/advisories/GHSA-test",
            "epss_score": epss_score,
            "epss_percentile": 0.9,
        },
        "candidate": {
            "package": package,
            "from_version": "1.0.0",
            "to_version": "1.0.1",
            "fix_kind": "patch",
            "trust_subscore": 50,
            "max_epss_score": epss_score,
            "candidate_id": f"cand-{package}-001",
        },
        "verdict": {
            "score": 40,
            "tier": tier,
            "veto_signals": veto_signals,
            "reasons": ["test reason"],
            "candidate_id": f"cand-{package}-001",
        },
    }


def _cached_scan_dict(
    *,
    entries: list[dict[str, Any]] | None = None,
    project_scores: dict[str, Any] | None = None,
    total_findings: int | None = None,
) -> dict[str, Any]:
    entries = entries or []
    count = total_findings if total_findings is not None else len(entries)
    payload = {
        "repo_path": "/tmp/repo",
        "lockfile_path": "/tmp/repo/package-lock.json",
        "entries": entries,
        "skipped_findings": [],
        "summary": {
            "total_findings": count,
            "total_candidates": count,
            "auto_merge_count": 0,
            "review_required_count": count,
            "decline_count": 0,
            "kev_count": sum(1 for e in entries if (e.get("finding") or {}).get("is_kev")),
            "max_epss_score": 0.21,
        },
        "project_scores": project_scores
        or {
            "prs": 62,
            "vulnerability_subscore": 70,
            "trust_subscore": 50,
            "pipeline_subscore": 100,
            "test_reality": "vetoed",
        },
        "executive_summary": "Test executive summary.",
        "lens_explain": {
            "vulnerability": {
                "findings": [
                    {
                        "advisory_id": "GHSA-test",
                        "package": "left-pad",
                        "cvss_score": 7.0,
                        "normalized_score": 70.0,
                    }
                ]
            },
            "trust": {
                "packages": [
                    {"name": "left-pad", "version": "1.0.0", "subscore": 50},
                ]
            },
            "pipeline": {
                "workflow_files": [".github/workflows/ci.yml"],
                "zizmor_counts": {},
                "zizmor_weighted_sum": 0,
                "test_penalty": 40,
                "subscore": 40,
                "test_reality": {
                    "has_test_script": False,
                    "test_script_is_no_op": True,
                    "has_test_files": False,
                    "test_count": 0,
                    "workflow_runs_tests": False,
                    "safe_to_auto_merge": False,
                    "reasons_blocked": ["no test script"],
                },
            },
        },
        "scan_meta": {
            "repo_display": "expressjs/express",
            "ref": "HEAD",
            "mode": "A",
            "completed_at": _FIXED_TIME.isoformat(),
            "dep_counts": {"direct": 2, "transitive": 5},
        },
    }
    return attach_minimal_scan_counts(payload, total_findings=total_findings)


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def _candidate(*, package: str = "left-pad") -> FixCandidate:
    return FixCandidate(
        package=package,
        from_version="1.3.0",
        to_version="1.3.1",
        fix_kind=FixKind.PATCH,
        source_finding_ids=("GHSA-test",),
        repo_id="/tmp/repo",
    )


def _finding(
    *,
    package: str = "left-pad",
    epss_score: float | None = None,
) -> Finding:
    return Finding(
        dependency=Dependency(name=package, version="1.3.0", direct=True),
        lens="cve",
        severity="high",
        score=75.0,
        title="GHSA-test: test vulnerability",
        description="test description",
        advisory_id="GHSA-test",
        source_url="https://github.com/advisories/GHSA-test",
        cve_id="CVE-2024-0001" if epss_score is not None else None,
        epss_score=epss_score,
        epss_percentile=0.9 if epss_score is not None else None,
    )


def _verdict(candidate: FixCandidate, *, tier: FixTier) -> FixConfidence:
    return FixConfidence(
        candidate_id=candidate.candidate_id,
        tier=tier,
        score=95,
        reasons=("trust and pipeline signals are clean",),
        veto_signals=(),
        evaluated_at=_FIXED_TIME,
        engine_version=ENGINE_VERSION,
    )


def _proposal_entry(
    *,
    tier: FixTier,
    package: str = "left-pad",
    epss_score: float | None = None,
) -> ProposalEntry:
    candidate = _candidate(package=package)
    if epss_score is not None:
        candidate = FixCandidate(
            package=candidate.package,
            from_version=candidate.from_version,
            to_version=candidate.to_version,
            fix_kind=candidate.fix_kind,
            source_finding_ids=candidate.source_finding_ids,
            repo_id=candidate.repo_id,
            max_epss_score=epss_score,
            max_epss_percentile=0.9,
        )
    finding = _finding(package=package, epss_score=epss_score)
    verdict = _verdict(candidate, tier=tier)
    return ProposalEntry(
        finding=finding, related_findings=(finding,), candidate=candidate, verdict=verdict
    )


def _proposal_report(
    repo: Path,
    entries: tuple[ProposalEntry, ...] = (),
    project_scores: ProjectScores | None = _DEFAULT_PROJECT_SCORES,
) -> ProposalReport:
    auto = sum(1 for e in entries if e.verdict.tier is FixTier.AUTO_MERGE)
    review = sum(1 for e in entries if e.verdict.tier is FixTier.REVIEW_REQUIRED)
    decline = sum(1 for e in entries if e.verdict.tier is FixTier.DECLINE)
    return ProposalReport(
        repo_path=str(repo),
        lockfile_path=str(repo / "package-lock.json"),
        entries=entries,
        skipped_findings=(),
        summary=ProposalSummary(
            total_findings=len(entries),
            total_candidates=len(entries),
            auto_merge_count=auto,
            review_required_count=review,
            decline_count=decline,
        ),
        project_scores=project_scores,
    )


async def _mock_fetch_inputs(owner: str, repo: str, ref: str, dest: Path) -> RepoInputs:
    dest.mkdir(parents=True, exist_ok=True)
    lockfile = dest / "package-lock.json"
    lockfile.write_bytes((_FIXTURES / "minimal.json").read_bytes())
    return RepoInputs(work_tree=dest, lockfile_path=lockfile)


def _mock_clone_with_lockfile(dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "package-lock.json").write_bytes((_FIXTURES / "minimal.json").read_bytes())
    return dest


def test_landing_page_returns_html(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == status.HTTP_200_OK
    assert "text/html" in response.headers["content-type"]
    body = response.text
    assert "Knows when to merge" in body
    assert 'href="/scan"' in body


def test_home_page_renders_with_nav_and_footer(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == status.HTTP_200_OK
    assert "ARGUSS" in response.text
    assert 'href="/how-it-works"' in response.text
    assert 'href="/about"' in response.text
    assert "Knows when to merge" in response.text


def test_how_it_works_page_renders_real_content(client: TestClient) -> None:
    response = client.get("/how-it-works")
    assert response.status_code == status.HTTP_200_OK
    text = response.text
    assert "Three lenses. One decision." in text
    assert "Vulnerability" in text
    assert "Trust" in text
    assert "Pipeline" in text
    assert "fix-confidence" in text
    assert "CVSS" in text
    assert "EPSS" in text
    assert "KEV" in text


def test_how_it_works_includes_scoring_ladder(client: TestClient) -> None:
    response = client.get("/how-it-works")
    assert response.status_code == status.HTTP_200_OK
    text = response.text
    assert "AUTO_MERGE" in text
    assert "REVIEW_REQUIRED" in text
    assert "100" in text and "75" in text and "1" in text


def test_about_page_renders_real_content(client: TestClient) -> None:
    response = client.get("/about")
    assert response.status_code == status.HTTP_200_OK
    text = response.text
    assert "Adrian Rosales" in text
    assert "Sherbano Khan" in text
    assert ("Huiping" in text) or ("Sophia" in text)
    assert "CYBER 295" in text
    assert "FastAPI" in text
    assert "Ohm" in text


def test_about_includes_team_names(client: TestClient) -> None:
    response = client.get("/about")
    assert response.status_code == status.HTTP_200_OK
    text = response.text
    assert "Adrian Rosales" in text
    assert "Sherbano Khan" in text
    assert ("Huiping" in text) or ("Sophia" in text)


def test_about_includes_references(client: TestClient) -> None:
    response = client.get("/about")
    assert response.status_code == status.HTTP_200_OK
    text = response.text
    assert "Ohm" in text
    assert "Executive Order 14028" in text


def test_scan_page_renders_with_entry_tabs(client: TestClient) -> None:
    response = client.get("/scan")
    assert response.status_code == status.HTTP_200_OK
    text = response.text
    assert "mode-tab" in text
    assert ">Scan<" in text or ">Scan</span>" in text
    assert "Upload" in text
    mode_tabs = text.split('class="mode-tabs"', 1)[1].split("</div>", 1)[0]
    assert "Scan with action" not in mode_tabs


def test_scan_page_marks_scan_tab_active(client: TestClient) -> None:
    response = client.get("/scan")
    assert "mode-tab-active" in response.text


def test_upload_page_marks_upload_tab_active(client: TestClient) -> None:
    response = client.get("/upload")
    assert "mode-tab-active" in response.text


def test_action_page_still_renders_without_entry_tab(client: TestClient) -> None:
    response = client.get("/action")
    assert response.status_code == status.HTTP_200_OK
    assert 'name="pat"' in response.text
    assert "Scan with action" in response.text


def test_scan_page_demo_query_prefills_url(client: TestClient) -> None:
    response = client.get("/scan?demo=axios")
    assert response.status_code == status.HTTP_200_OK
    assert "axios/axios" in response.text


def test_scan_page_includes_ref_field(client: TestClient) -> None:
    response = client.get("/scan")
    assert response.status_code == status.HTTP_200_OK
    text = response.text
    assert 'name="ref"' in text
    assert "Branch, tag, or commit" in text


def test_scan_page_demo_does_not_prefill_ref(client: TestClient) -> None:
    """demo= only pre-fills the repo URL; ref defaults to HEAD unless ref= is set."""
    response = client.get("/scan?demo=axios")
    assert response.status_code == status.HTTP_200_OK
    text = response.text
    assert "axios/axios" in text
    assert 'value="v1.0.0"' not in text


def test_scan_page_ref_query_prefills_ref(client: TestClient) -> None:
    response = client.get("/scan?ref=v1.0.0")
    assert response.status_code == status.HTTP_200_OK
    assert 'value="v1.0.0"' in response.text


def test_scan_page_demo_and_ref_query_prefill_both(client: TestClient) -> None:
    response = client.get("/scan?demo=axios&ref=v1.0.0")
    assert response.status_code == status.HTTP_200_OK
    text = response.text
    assert "axios/axios" in text
    assert 'value="v1.0.0"' in text


def test_action_page_includes_ref_field(client: TestClient) -> None:
    response = client.get("/action")
    assert response.status_code == status.HTTP_200_OK
    text = response.text
    assert 'name="ref"' in text
    assert "Branch, tag, or commit" in text


def test_workflows_zip_ignores_macos_metadata_files(
    client: TestClient,
    tmp_path: Path,
) -> None:
    """Dashboard upload must not reject zips that include macOS Finder metadata."""
    import io
    import zipfile

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr(".github/workflows/ci.yml", "name: CI\non: push\njobs: {}\n")
        zf.writestr("__MACOSX/.github/workflows/._ci.yml", b"\x00\x05\x16\x07")
        zf.writestr(".github/workflows/._ci.yml", b"\x00\x05\x16\x07")
        zf.writestr("._workflows", b"\x00\x05\x16\x07")
    zip_buf.seek(0)

    lockfile_bytes = (_FIXTURES / "minimal.json").read_bytes()
    report = _proposal_report(
        tmp_path / "repo",
        (_proposal_entry(tier=FixTier.REVIEW_REQUIRED, package="chalk"),),
    )

    with mock.patch.object(dashboard_mod, "propose_fixes", return_value=report):
        response = client.post(
            "/dashboard/upload",
            files={
                "lockfile": ("package-lock.json", lockfile_bytes, "application/json"),
                "workflows_zip": ("workflows.zip", zip_buf.getvalue(), "application/zip"),
            },
        )

    assert response.status_code == status.HTTP_200_OK, response.text
    assert "must be a .yml or .yaml file" not in response.text


def test_scan_page_preserves_existing_form(client: TestClient) -> None:
    response = client.get("/scan")
    assert response.status_code == status.HTTP_200_OK
    assert 'name="url"' in response.text


def test_scan_page_does_not_render_none_in_input_values(client: TestClient) -> None:
    response = client.get("/scan")
    assert response.status_code == status.HTTP_200_OK
    assert 'value="None"' not in response.text


def test_upload_page_preserves_existing_form(client: TestClient) -> None:
    response = client.get("/upload")
    assert response.status_code == status.HTTP_200_OK
    assert 'name="lockfile"' in response.text


def test_upload_page_has_required_lockfile_input(client: TestClient) -> None:
    response = client.get("/upload")
    assert 'name="lockfile"' in response.text
    assert "required" in response.text


def test_action_page_preserves_existing_form(client: TestClient) -> None:
    response = client.get("/action")
    assert response.status_code == status.HTTP_200_OK
    assert 'name="pat"' in response.text


def test_action_page_preserves_pat_features(client: TestClient) -> None:
    response = client.get("/action")
    text = response.text
    assert 'name="pat"' in text
    assert "personal-access-tokens/new" in text
    assert "scope-badge" in text or "Contents" in text
    assert 'id="action-submit"' in text
    assert "disabled" in text


def test_all_mode_pages_have_loading_indicator(client: TestClient) -> None:
    for path in ("/scan", "/upload", "/action"):
        response = client.get(path)
        assert "htmx-indicator" in response.text or "loading-indicator" in response.text


def test_scan_page_loading_includes_rotating_messages(client: TestClient) -> None:
    response = client.get("/scan")
    text = response.text
    assert "Analyzing your dependencies..." in text
    assert "Querying OSV.dev" in text
    assert "Computing TrustDelta" in text


def test_action_page_loading_includes_action_layer_messages(client: TestClient) -> None:
    response = client.get("/action")
    text = response.text
    assert "Opening pull requests" in text
    assert "Waiting on your CI" in text


def test_upload_page_loading_includes_analysis_messages(client: TestClient) -> None:
    response = client.get("/upload")
    assert "Analyzing your dependencies..." in response.text


def test_mode_pages_lock_submit_during_htmx_request(client: TestClient) -> None:
    """Base layout disables scan-form submit buttons while an HTMX request is in flight."""
    response = client.get("/scan")
    assert response.status_code == status.HTTP_200_OK
    assert "htmx:beforeRequest" in response.text
    assert "argussLocked" in response.text
    assert "scan-demo-btn" in response.text
    assert "HX-Redirect" in response.text


def test_scan_page_demo_button_submits_via_script(client: TestClient) -> None:
    """Demo control fills axios fields and auto-starts scan; not a navigation link."""
    response = client.get("/scan")
    assert response.status_code == status.HTTP_200_OK
    text = response.text
    assert 'id="scan-form"' in text
    assert 'id="scan-demo-btn"' in text
    assert "initScanDemoFlow" in text
    assert 'type="button"' in text
    assert "Try the demo target" in text
    assert 'href="/scan?demo=axios' not in text


def test_static_logo_is_served(client: TestClient) -> None:
    response = client.get("/static/arguss-logo.png")
    assert response.status_code == status.HTTP_200_OK
    assert response.headers["content-type"].startswith("image/")


def test_action_page_includes_pat_generation_link(client: TestClient) -> None:
    """Mode C section should link to GitHub's PAT generation page with pre-filled params."""
    response = client.get("/action")
    assert response.status_code == status.HTTP_200_OK
    assert "github.com/settings/personal-access-tokens/new" in response.text
    assert "description=Arguss" in response.text


def test_action_page_includes_pat_security_notice(client: TestClient) -> None:
    """Mode C section should reassure users that PAT is session-only."""
    response = client.get("/action")
    assert response.status_code == status.HTTP_200_OK
    assert "never stores your PAT" in response.text


def test_action_page_includes_pat_scope_guidance(client: TestClient) -> None:
    """Mode C section should explain which scopes Arguss needs."""
    response = client.get("/action")
    assert response.status_code == status.HTTP_200_OK
    assert "Contents" in response.text
    assert "Pull requests" in response.text


def test_scan_post_returns_hx_redirect(client: TestClient, tmp_path: Path) -> None:
    report = _proposal_report(
        tmp_path / "repo",
        (_proposal_entry(tier=FixTier.AUTO_MERGE, package="left-pad"),),
    )

    with (
        mock.patch.object(dashboard_mod, "fetch_repo_inputs", side_effect=_mock_fetch_inputs),
        mock.patch.object(dashboard_mod, "propose_fixes", return_value=report),
        mock.patch.object(
            dashboard_mod,
            "attach_executive_summary",
            side_effect=_stub_attach_executive_summary,
        ),
    ):
        response = client.post(
            "/dashboard/scan",
            data={"url": _EXPRESS_URL, "ref": "HEAD"},
        )

    assert response.status_code == status.HTTP_200_OK
    assert response.headers.get("HX-Redirect", "").startswith("/assessment/")


def _enriched_deps_for_graph() -> list[dict[str, Any]]:
    return [
        {
            "package": "left-pad",
            "version": "1.0.0",
            "is_direct": True,
            "parents": ["root"],
            "path": ["root", "left-pad"],
        },
    ]


def _results_page(client: TestClient, scan_hash: str = "polish-demo-hash") -> Any:
    scan = _cached_scan_dict(entries=[_cached_entry(package="left-pad")])
    scan["deps"] = _enriched_deps_for_graph()
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        return client.get(f"/assessment/{scan_hash}")


def test_results_page_renders_for_valid_hash(client: TestClient) -> None:
    scan = _cached_scan_dict(entries=[_cached_entry(package="left-pad")])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/deadbeef")

    assert response.status_code == status.HTTP_200_OK
    assert "Project Risk Score" in response.text
    assert "Executive summary" in response.text or "exec-summary" in response.text
    assert "Findings" in response.text


def test_results_page_404_for_unknown_hash(client: TestClient) -> None:
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=None):
        response = client.get("/assessment/nonexistent-hash-12345")

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in response.text.lower()
    assert "Run a new scan" in response.text


def test_results_page_renders_empty_state_for_zero_findings(client: TestClient) -> None:
    scan = _cached_scan_dict(entries=[], total_findings=0)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/empty-scan")

    assert response.status_code == status.HTTP_200_OK
    assert "No vulnerabilities found" in response.text


def test_results_page_marks_ownership_transfer_packages(client: TestClient) -> None:
    scan = _cached_scan_dict(
        entries=[
            _cached_entry(
                package="path-to-regexp",
                veto_signals=("trust.ownership_transferred",),
            )
        ],
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/trust-demo")

    assert "demo-moment" in response.text or "TRUST SAVE" in response.text


def test_results_page_marks_kev_packages(client: TestClient) -> None:
    scan = _cached_scan_dict(entries=[_cached_entry(package="qs", is_kev=True)])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/kev-demo")

    assert "has-kev" in response.text


def test_results_page_has_share_button(client: TestClient) -> None:
    response = _results_page(client)
    assert response.status_code == status.HTTP_200_OK
    assert 'id="share-button"' in response.text
    assert "Copy link" in response.text


def test_results_page_has_back_to_top(client: TestClient) -> None:
    response = _results_page(client)
    assert response.status_code == status.HTTP_200_OK
    assert 'id="back-to-top"' in response.text


def test_results_page_has_package_search(client: TestClient) -> None:
    response = _results_page(client)
    assert response.status_code == status.HTTP_200_OK
    assert 'id="package-search"' in response.text


def test_results_page_has_expand_close_all(client: TestClient) -> None:
    response = _results_page(client)
    assert response.status_code == status.HTTP_200_OK
    assert 'id="expand-all"' in response.text
    assert 'id="close-all"' in response.text


def test_results_page_has_sort_dropdown(client: TestClient) -> None:
    response = _results_page(client)
    assert response.status_code == status.HTTP_200_OK
    assert 'id="sort-select"' in response.text
    assert 'value="severity"' in response.text
    assert 'value="findings"' in response.text
    assert "Finding count" in response.text
    assert 'value="default"' in response.text
    assert 'value="trust"' in response.text
    assert 'value="epss"' in response.text


def test_results_page_has_glossary_section(client: TestClient) -> None:
    response = _results_page(client)
    assert response.status_code == status.HTTP_200_OK
    text = response.text
    assert 'id="glossary"' in text
    assert "glossary-details" in text
    assert "glossary-expand-when-closed" in text
    assert '<details class="glossary glossary-details" id="glossary">' in text
    assert " open" not in text.split('id="glossary"')[1].split(">")[0]
    assert "glossary-trust-save" in text
    assert "glossary-epss" in text
    assert "Trust Save" in text


def test_results_page_has_sbom_download_link(client: TestClient) -> None:
    """Covered in tests/web/test_sbom_download.py."""
    pass


def test_results_page_has_dependency_graph_placeholder(client: TestClient) -> None:
    response = _results_page(client)
    assert response.status_code == status.HTTP_200_OK
    assert "Dependency graph" in response.text
    assert "Load graph" in response.text
    assert 'id="dependency-graph-load"' in response.text
    assert "dependency-graph-data" in response.text
    section_start = response.text.index('class="dependency-graph-section"')
    section_end = response.text.index("</section>", section_start)
    graph_section = response.text[section_start:section_end]
    assert "Coming soon" not in graph_section
    assert 'data-default-show-all="false"' in graph_section
    assert "dependency-graph-show-all" in graph_section
    assert 'id="dependency-graph-show-all"' in graph_section


def test_clean_scan_dependency_graph_defaults_to_show_all(client: TestClient) -> None:
    scan = _cached_scan_dict(entries=[], total_findings=0)
    scan["deps"] = _enriched_deps_for_graph()
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/clean-graph")

    assert response.status_code == status.HTTP_200_OK
    section_start = response.text.index('class="dependency-graph-section"')
    section_end = response.text.index("</section>", section_start)
    graph_section = response.text[section_start:section_end]
    assert "Load graph" in graph_section
    assert 'data-default-show-all="true"' in graph_section
    assert "dependency-graph-show-all" not in graph_section
    assert "Show all dependencies" not in graph_section


def test_package_row_includes_current_version(client: TestClient) -> None:
    response = _results_page(client)
    assert response.status_code == status.HTTP_200_OK
    assert "package-current-version" in response.text
    assert "@ 1.0.0" in response.text


def test_ordinal_helper() -> None:
    from arguss.web.results_context import ordinal

    assert ordinal(1) == "1st"
    assert ordinal(2) == "2nd"
    assert ordinal(3) == "3rd"
    assert ordinal(11) == "11th"
    assert ordinal(21) == "21st"
    assert ordinal(82) == "82nd"
    assert ordinal(100) == "100th"


def test_project_scores_exposes_test_reality_field() -> None:
    assert "test_reality" in {field.name for field in fields(ProjectScores)}


def test_dashboard_renders_epss_badge(client: TestClient) -> None:
    scan = _cached_scan_dict(entries=[_cached_entry(epss_score=0.21)])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/epss-demo")

    assert response.status_code == status.HTTP_200_OK
    assert "finding-epss-high" in response.text
    assert "EPSS 21.0%" in response.text
    assert "probability" in response.text
    assert "90th percentile" in response.text


def test_dashboard_scan_error_renders_error_template(client: TestClient) -> None:
    with mock.patch.object(
        dashboard_mod,
        "fetch_repo_inputs",
        side_effect=GitHubFetchError("Repository or ref not found", 404),
    ):
        response = client.post(
            "/dashboard/scan",
            data={"url": _EXPRESS_URL, "ref": "HEAD"},
        )

    assert response.status_code == status.HTTP_200_OK
    assert "error-card" in response.text
    assert "Repository or ref not found" in response.text


def test_dashboard_upload_returns_hx_redirect(client: TestClient, tmp_path: Path) -> None:
    report = _proposal_report(
        tmp_path / "repo",
        (_proposal_entry(tier=FixTier.REVIEW_REQUIRED, package="chalk"),),
    )
    lockfile_bytes = (_FIXTURES / "minimal.json").read_bytes()

    with (
        mock.patch.object(dashboard_mod, "propose_fixes", return_value=report),
        mock.patch.object(
            dashboard_mod,
            "attach_executive_summary",
            side_effect=_stub_attach_executive_summary,
        ),
    ):
        response = client.post(
            "/dashboard/upload",
            files={"lockfile": ("package-lock.json", lockfile_bytes, "application/json")},
        )

    assert response.status_code == status.HTTP_200_OK
    assert response.headers.get("HX-Redirect", "").startswith("/assessment/")


def test_dashboard_scan_with_action_renders_results_with_actions(
    client: TestClient,
    tmp_path: Path,
) -> None:
    auto = _proposal_entry(tier=FixTier.AUTO_MERGE, package="left-pad")
    report = _proposal_report(tmp_path / "repo", (auto,))
    opened = ActionResult(
        candidate_id=auto.candidate.candidate_id,
        status="opened",
        pr_url="https://github.com/o/r/pull/1",
        pr_number=1,
        reason=None,
    )

    scan_result = ScanWithActionResult(
        report=report,
        actions=[opened],
        payload=proposal_report_with_actions_payload(report, [opened]),
        scan_hash="dashboard-mode-c-hash",
    )
    with (
        mock.patch.object(
            dashboard_mod,
            "execute_scan_with_action",
            return_value=scan_result,
        ),
        mock.patch.object(
            dashboard_mod,
            "attach_executive_summary",
            side_effect=_stub_attach_executive_summary,
        ),
    ):
        response = client.post(
            "/dashboard/scan-with-action",
            data={"url": _EXPRESS_URL, "ref": "HEAD", "pat": _TEST_PAT},
        )

    assert response.status_code == status.HTTP_200_OK
    redirect = response.headers.get("HX-Redirect", "")
    assert redirect.startswith("/assessment/")

    scan = _cached_scan_dict(
        entries=[_cached_entry(package="left-pad", tier="auto_merge")],
    )
    scan["actions"] = [
        {
            "candidate_id": opened.candidate_id,
            "status": "opened",
            "pr_url": opened.pr_url,
            "pr_number": opened.pr_number,
            "reason": None,
        }
    ]
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        page = client.get(redirect)

    assert page.status_code == status.HTTP_200_OK
    assert "actions-section" in page.text
    assert "opened" in page.text


def test_group_by_package_summary_tier_logic() -> None:
    repo = Path("/tmp/repo")
    same_tier = (
        _proposal_entry(tier=FixTier.AUTO_MERGE, package="pkg-a"),
        _proposal_entry(tier=FixTier.AUTO_MERGE, package="pkg-a"),
    )
    mixed = (
        _proposal_entry(tier=FixTier.AUTO_MERGE, package="pkg-b"),
        _proposal_entry(tier=FixTier.REVIEW_REQUIRED, package="pkg-b"),
    )
    report = _proposal_report(repo, same_tier + mixed)
    groups = dashboard_mod.group_by_package(report)
    by_name = {g.name: g.summary_tier for g in groups}
    assert by_name["pkg-a"] == "auto_merge"
    assert by_name["pkg-b"] == "mixed"


def test_dashboard_renders_prs_on_results_page(client: TestClient) -> None:
    scan = _cached_scan_dict(entries=[_cached_entry()])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/prs-demo")

    assert response.status_code == status.HTTP_200_OK
    assert "Project Risk Score" in response.text
    assert "62" in response.text
    assert "/100" in response.text


def test_dashboard_omits_prs_when_unavailable(client: TestClient) -> None:
    scan = _cached_scan_dict(
        entries=[_cached_entry()],
        project_scores={
            "prs": None,
            "vulnerability_subscore": 70,
            "trust_subscore": 50,
            "pipeline_subscore": 40,
            "test_reality": "not_applicable",
        },
    )
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/no-prs")

    assert response.status_code == status.HTTP_200_OK
    assert 'class="score-number tier-caution">62</span>' not in response.text


def test_results_page_has_glossary_tooltips(client: TestClient) -> None:
    """Glossary (?) icons should have rich hover tooltip content."""
    response = _results_page(client)
    assert response.status_code == status.HTTP_200_OK
    assert "glossary-tooltip" in response.text
    assert "Verdict tier: at least one veto" in response.text


def test_results_page_lens_tiles_are_buttons(client: TestClient) -> None:
    response = _results_page(client)
    assert response.status_code == status.HTTP_200_OK
    assert 'data-lens="vulnerability"' in response.text
    assert 'data-lens="trust"' in response.text
    assert 'data-lens="workflow_security"' in response.text
    assert 'data-lens="test_reality"' in response.text
    assert "<button" in response.text
    assert 'class="lens-tile' in response.text


def test_results_page_includes_breakdown_data(client: TestClient) -> None:
    response = _results_page(client)
    assert response.status_code == status.HTTP_200_OK
    assert 'id="lens-breakdowns-data"' in response.text
    assert '"vulnerability"' in response.text
    assert '"trust"' in response.text
    assert '"workflow_security"' in response.text
    assert '"test_reality"' in response.text


def test_results_page_has_lens_breakdown_panel(client: TestClient) -> None:
    response = _results_page(client)
    assert response.status_code == status.HTTP_200_OK
    assert 'id="lens-breakdown"' in response.text
    assert 'id="lens-breakdown-title"' in response.text


def test_build_vulnerability_breakdown_produces_consistent_math() -> None:
    from arguss.web.results_context import build_vulnerability_breakdown

    cached = {
        "project_scores": {"vulnerability_subscore": 70},
        "lens_explain": {
            "vulnerability": {
                "findings": [
                    {
                        "advisory_id": "GHSA-test",
                        "package": "left-pad",
                        "cvss_score": 7.0,
                        "normalized_score": 70.0,
                    }
                ]
            }
        },
    }
    breakdown = build_vulnerability_breakdown(cached)
    assert breakdown.final_value == 70


def test_build_test_reality_breakdown_has_four_conditions() -> None:
    from arguss.web.results_context import build_test_reality_breakdown

    cached = {
        "project_scores": {"test_reality": "vetoed"},
        "lens_explain": {
            "pipeline": {
                "workflow_files": [".github/workflows/ci.yml"],
                "test_reality": {
                    "has_test_script": False,
                    "test_script_is_no_op": True,
                    "has_test_files": False,
                    "test_count": 0,
                    "workflow_runs_tests": False,
                },
            }
        },
    }
    breakdown = build_test_reality_breakdown(cached)
    assert len(breakdown.lines) == 4
    assert breakdown.final_value == "vetoed"


def test_mode_b_lockfile_error_renders_error_card(client: TestClient) -> None:
    """Mode B upload with unsupported lockfile renders the styled error card."""
    fake_lockfile = b'{"name": "test", "lockfileVersion": 1, "requires": true}'
    response = client.post(
        "/dashboard/upload",
        files={"lockfile": ("package-lock.json", fake_lockfile, "application/json")},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "error-card" in response.text
    assert "lockfile" in response.text.lower()
    assert "mode a" in response.text.lower()


def test_chat_system_prompt_includes_zizmor_mapping() -> None:
    from arguss.explanations.chat import _SYSTEM_PROMPT_TEMPLATE

    assert "zizmor" in _SYSTEM_PROMPT_TEMPLATE.lower()
    assert "pipeline" in _SYSTEM_PROMPT_TEMPLATE.lower()
    assert "workflow security" in _SYSTEM_PROMPT_TEMPLATE.lower()


def test_unknown_page_returns_html_404(client: TestClient) -> None:
    response = client.get("/this-page-does-not-exist-xyz")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "text/html" in response.headers.get("content-type", "")
    assert "Page not found" in response.text
    assert "results-not-found-code" in response.text
    assert "Go home" in response.text


def test_unknown_page_html_404_with_accept_header(client: TestClient) -> None:
    response = client.get(
        "/another-missing-route",
        headers={"Accept": "text/html,application/xhtml+xml"},
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "text/html" in response.headers.get("content-type", "")
    assert "Page not found" in response.text


def test_results_page_renders_package_blast_radius_when_deps_enriched(client: TestClient) -> None:
    from pathlib import Path

    from arguss.web.url_scan import serialize_lockfile_deps

    lockfile = Path(__file__).resolve().parent / "fixtures" / "lockfiles" / "real-world.json"
    entry = _cached_entry(package="debug")
    entry["finding"]["dependency"]["version"] = "2.6.9"
    entry["candidate"]["from_version"] = "2.6.9"
    scan = _cached_scan_dict(entries=[entry])
    scan["deps"] = serialize_lockfile_deps(lockfile)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/blast-radius-demo")

    assert response.status_code == status.HTTP_200_OK
    assert 'class="package-blast-radius"' in response.text
    assert (
        'class="package-blast-radius-data"' in response.text
        or "package-blast-radius-data" in response.text
    )
    assert "cdn.jsdelivr.net/npm/cytoscape" in response.text
    assert "integrity=" in response.text
    assert "crossorigin=" in response.text
    assert "cytoscape.min.js" in response.text
    assert "bootBlastRadiusGraphs" in response.text


def test_results_page_omits_blast_radius_without_enriched_deps(client: TestClient) -> None:
    scan = _cached_scan_dict(entries=[_cached_entry(package="left-pad")])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/no-graph-deps")

    assert response.status_code == status.HTTP_200_OK
    assert 'class="package-blast-radius"' not in response.text


def test_results_page_renders_blast_radius_on_zero_findings(client: TestClient) -> None:
    from pathlib import Path

    from arguss.web.url_scan import serialize_lockfile_deps
    from tests.fixtures.scan_counts_helpers import attach_minimal_scan_counts

    lockfile = Path(__file__).resolve().parent / "fixtures" / "lockfiles" / "real-world.json"
    scan = _cached_scan_dict(entries=[], total_findings=0)
    scan["deps"] = serialize_lockfile_deps(lockfile)
    scan = attach_minimal_scan_counts(scan, total_findings=0)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/clean-blast-radius")

    assert response.status_code == status.HTTP_200_OK
    assert "No vulnerabilities found" in response.text
    assert 'class="package-blast-radius"' in response.text
    assert "Dependencies" in response.text
    assert "bootBlastRadiusGraphs" in response.text
