"""Tests for HTML dashboard routes."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
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
from arguss.engine.fix_confidence import ENGINE_VERSION
from arguss.engine.propose import ProposalEntry, ProposalReport, ProposalSummary
from arguss.web.github_action import ActionResult
from arguss.web.github_fetch import GitHubFetchError, RepoInputs

_EXPRESS_URL = "https://github.com/expressjs/express"
_TEST_PAT = "ghp_test_pat_for_unit_tests_only_not_real"

_DEFAULT_PROJECT_SCORES = ProjectScores(
    prs=62,
    vulnerability_subscore=70,
    trust_subscore=50,
    pipeline_subscore=40,
)
_FIXED_TIME = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)
_FIXTURES = Path(__file__).parent / "fixtures" / "lockfiles"


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def _candidate(*, package: str = "left-pad") -> FixCandidate:
    return FixCandidate(
        package=package,
        from_version="1.3.0",
        to_version="1.3.1",
        fix_kind=FixKind.PATCH,
        source_finding_id="GHSA-test",
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
            source_finding_id=candidate.source_finding_id,
            repo_id=candidate.repo_id,
            max_epss_score=epss_score,
            max_epss_percentile=0.9,
        )
    finding = _finding(package=package, epss_score=epss_score)
    verdict = _verdict(candidate, tier=tier)
    return ProposalEntry(finding=finding, candidate=candidate, verdict=verdict)


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
    assert "/dashboard/scan" in body
    assert "/dashboard/upload" in body
    assert "/dashboard/scan-with-action" in body


def test_landing_page_includes_pat_generation_link(client: TestClient) -> None:
    """Mode C section should link to GitHub's PAT generation page with pre-filled params."""
    response = client.get("/")
    assert response.status_code == status.HTTP_200_OK
    assert "github.com/settings/personal-access-tokens/new" in response.text
    assert "description=Arguss" in response.text


def test_landing_page_includes_pat_security_notice(client: TestClient) -> None:
    """Mode C section should reassure users that PAT is session-only."""
    response = client.get("/")
    assert response.status_code == status.HTTP_200_OK
    assert "never stores your PAT" in response.text


def test_landing_page_includes_pat_scope_guidance(client: TestClient) -> None:
    """Mode C section should explain which scopes Arguss needs."""
    response = client.get("/")
    assert response.status_code == status.HTTP_200_OK
    assert "Contents" in response.text
    assert "Pull requests" in response.text


def test_dashboard_scan_renders_results(client: TestClient, tmp_path: Path) -> None:
    report = _proposal_report(
        tmp_path / "repo",
        (_proposal_entry(tier=FixTier.AUTO_MERGE, package="left-pad"),),
    )

    with (
        mock.patch.object(dashboard_mod, "fetch_repo_inputs", side_effect=_mock_fetch_inputs),
        mock.patch.object(dashboard_mod, "propose_fixes", return_value=report),
    ):
        response = client.post(
            "/dashboard/scan",
            data={"url": _EXPRESS_URL, "ref": "HEAD"},
        )

    assert response.status_code == status.HTTP_200_OK
    assert "summary-banner" in response.text
    assert "package-row" in response.text


def test_dashboard_renders_epss_badge(client: TestClient, tmp_path: Path) -> None:
    report = _proposal_report(
        tmp_path / "repo",
        (_proposal_entry(tier=FixTier.REVIEW_REQUIRED, epss_score=0.21),),
    )

    with (
        mock.patch.object(dashboard_mod, "fetch_repo_inputs", side_effect=_mock_fetch_inputs),
        mock.patch.object(dashboard_mod, "propose_fixes", return_value=report),
    ):
        response = client.post(
            "/dashboard/scan",
            data={"url": _EXPRESS_URL, "ref": "HEAD"},
        )

    assert response.status_code == status.HTTP_200_OK
    assert "finding-epss-high" in response.text
    assert "EPSS 21.0%" in response.text


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
    assert "Scan failed:" in response.text
    assert "Repository or ref not found" in response.text


def test_dashboard_upload_renders_results(client: TestClient, tmp_path: Path) -> None:
    report = _proposal_report(
        tmp_path / "repo",
        (_proposal_entry(tier=FixTier.REVIEW_REQUIRED, package="chalk"),),
    )
    lockfile_bytes = (_FIXTURES / "minimal.json").read_bytes()

    with mock.patch.object(dashboard_mod, "propose_fixes", return_value=report):
        response = client.post(
            "/dashboard/upload",
            files={"lockfile": ("package-lock.json", lockfile_bytes, "application/json")},
        )

    assert response.status_code == status.HTTP_200_OK
    assert "summary-banner" in response.text
    assert "package-row" in response.text


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

    with (
        mock.patch.object(
            dashboard_mod,
            "shallow_clone",
            side_effect=lambda _url, dest: _mock_clone_with_lockfile(dest),
        ),
        mock.patch.object(dashboard_mod, "propose_fixes", return_value=report),
        mock.patch.object(dashboard_mod, "open_fix_pr", return_value=opened),
    ):
        response = client.post(
            "/dashboard/scan-with-action",
            data={"url": _EXPRESS_URL, "ref": "HEAD", "pat": _TEST_PAT},
        )

    assert response.status_code == status.HTTP_200_OK
    assert "summary-banner" in response.text
    assert "actions-section" in response.text
    assert "opened" in response.text


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


def test_dashboard_renders_prs_badge(client: TestClient, tmp_path: Path) -> None:
    report = _proposal_report(
        tmp_path / "repo",
        (_proposal_entry(tier=FixTier.AUTO_MERGE, package="left-pad"),),
    )

    with (
        mock.patch.object(dashboard_mod, "fetch_repo_inputs", side_effect=_mock_fetch_inputs),
        mock.patch.object(dashboard_mod, "propose_fixes", return_value=report),
    ):
        response = client.post(
            "/dashboard/scan",
            data={"url": _EXPRESS_URL, "ref": "HEAD"},
        )

    assert response.status_code == status.HTTP_200_OK
    body = response.text
    assert "pill-prs" in body
    assert "Risk Score" in body
    assert "62/100" in body


def test_dashboard_omits_prs_when_unavailable(client: TestClient, tmp_path: Path) -> None:
    report = _proposal_report(
        tmp_path / "repo",
        (_proposal_entry(tier=FixTier.AUTO_MERGE, package="left-pad"),),
        project_scores=None,
    )

    with (
        mock.patch.object(dashboard_mod, "fetch_repo_inputs", side_effect=_mock_fetch_inputs),
        mock.patch.object(dashboard_mod, "propose_fixes", return_value=report),
    ):
        response = client.post(
            "/dashboard/scan",
            data={"url": _EXPRESS_URL, "ref": "HEAD"},
        )

    assert response.status_code == status.HTTP_200_OK
    assert "pill-prs" not in response.text
    assert "Risk Score" not in response.text
