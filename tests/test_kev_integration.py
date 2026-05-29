"""Integration tests for KEV enrichment across lens, propose, and dashboard."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from arguss.api import app
from arguss.core.models import (
    Dependency,
    Finding,
    FixCandidate,
    FixConfidence,
    FixKind,
    FixTier,
)
from arguss.engine.propose import (
    ProposalEntry,
    ProposalReport,
    ProposalSummary,
    _candidate_with_epss,
    _compute_kev_summary,
)
from arguss.lenses._kev_client import KevEntry
from arguss.lenses.vulnerability import VulnerabilityLens, _enrich_findings_with_kev
from arguss.web.dashboard import group_by_package


def _finding(
    *,
    package: str = "lodash",
    cve_id: str | None = "CVE-2024-0001",
    is_kev: bool = False,
    epss_score: float | None = None,
) -> Finding:
    return Finding(
        dependency=Dependency(name=package, version="1.0.0", direct=True),
        lens="cve",
        severity="high",
        score=75.0,
        title="GHSA-test: example",
        description="example",
        advisory_id="GHSA-1",
        cve_id=cve_id,
        epss_score=epss_score,
        epss_percentile=0.5 if epss_score is not None else None,
        is_kev=is_kev,
        kev_date_added="2021-12-10" if is_kev else None,
        kev_due_date="2021-12-24" if is_kev else None,
        kev_known_ransomware=is_kev,
    )


def test_finding_marked_is_kev_when_cve_in_catalog() -> None:
    findings = [_finding(cve_id="CVE-2021-44228")]

    async def fake_fetch(*args: object, **kwargs: object) -> dict[str, KevEntry]:
        return {
            "CVE-2021-44228": KevEntry(
                cve_id="CVE-2021-44228",
                date_added="2021-12-10",
                due_date="2021-12-24",
                known_ransomware=True,
            )
        }

    with mock.patch(
        "arguss.lenses.vulnerability.fetch_kev_catalog",
        side_effect=fake_fetch,
    ):
        enriched = _enrich_findings_with_kev(findings, mock.MagicMock())

    assert enriched[0].is_kev is True
    assert enriched[0].kev_date_added == "2021-12-10"
    assert enriched[0].kev_due_date == "2021-12-24"
    assert enriched[0].kev_known_ransomware is True


def test_finding_not_marked_when_cve_absent() -> None:
    findings = [_finding(cve_id="CVE-2024-9999")]

    async def fake_fetch(*args: object, **kwargs: object) -> dict[str, KevEntry]:
        return {
            "CVE-2021-44228": KevEntry(
                cve_id="CVE-2021-44228",
                date_added=None,
                due_date=None,
                known_ransomware=False,
            )
        }

    with mock.patch(
        "arguss.lenses.vulnerability.fetch_kev_catalog",
        side_effect=fake_fetch,
    ):
        enriched = _enrich_findings_with_kev(findings, mock.MagicMock())

    assert enriched[0].is_kev is False


def test_finding_not_marked_when_cve_id_is_none() -> None:
    findings = [_finding(cve_id=None)]

    async def fake_fetch(*args: object, **kwargs: object) -> dict[str, KevEntry]:
        return {
            "CVE-2021-44228": KevEntry(
                cve_id="CVE-2021-44228",
                date_added=None,
                due_date=None,
                known_ransomware=False,
            )
        }

    with mock.patch(
        "arguss.lenses.vulnerability.fetch_kev_catalog",
        side_effect=fake_fetch,
    ):
        enriched = _enrich_findings_with_kev(findings, mock.MagicMock())

    assert enriched[0].is_kev is False


def test_candidate_has_kev_finding_rollup() -> None:
    base = FixCandidate(
        package="pkg",
        from_version="1.0.0",
        to_version="1.0.1",
        fix_kind=FixKind.PATCH,
        source_finding_ids=("GHSA-1",),
        repo_id="/tmp/repo",
    )
    candidate = _candidate_with_epss(base, [_finding(is_kev=True)])
    assert candidate.has_kev_finding is True

    candidate_no_kev = _candidate_with_epss(base, [_finding(is_kev=False)])
    assert candidate_no_kev.has_kev_finding is False


def test_summary_kev_count_and_cve_ids() -> None:
    findings = [
        _finding(cve_id="CVE-2021-44228", is_kev=True),
        _finding(cve_id="CVE-2021-44228", is_kev=True, package="axios"),
        _finding(cve_id="CVE-2024-0001", is_kev=True, package="other"),
        _finding(cve_id="CVE-2024-9999", is_kev=False),
    ]
    count, cve_ids = _compute_kev_summary(findings)
    assert count == 3
    assert cve_ids == ("CVE-2021-44228", "CVE-2024-0001")


async def _mock_fetch_inputs(owner: str, repo: str, ref: str, dest: Path) -> object:
    from arguss.web.github_fetch import RepoInputs

    dest.mkdir(parents=True, exist_ok=True)
    lockfile = dest / "package-lock.json"
    lockfile.write_text(
        '{"lockfileVersion": 3, "packages": {"": {"name": "t", "version": "1.0.0"}}}',
        encoding="utf-8",
    )
    return RepoInputs(work_tree=dest, lockfile_path=lockfile)


def test_scan_completes_when_kev_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from arguss.core.cache import Cache, get_connection, init_db
    from arguss.core.models import LensScore

    async def empty_kev(*args: object, **kwargs: object) -> dict[str, KevEntry]:
        return {}

    monkeypatch.setattr(
        "arguss.lenses.vulnerability.fetch_kev_catalog",
        empty_kev,
    )

    mock_osv = mock.MagicMock()
    mock_osv.query_batch.return_value = {
        "lodash@4.17.20": [
            {
                "id": "GHSA-test",
                "summary": "test",
                "aliases": ["CVE-2024-0001"],
            }
        ]
    }

    conn = get_connection(":memory:")
    init_db(conn)
    cache = Cache(conn)
    lens = VulnerabilityLens(cache=cache, osv_client=mock_osv)
    result = lens.scan([Dependency(name="lodash", version="4.17.20", ecosystem="npm", direct=True)])

    assert isinstance(result, LensScore)
    assert result.findings[0].is_kev is False

    client = TestClient(app)
    with (
        mock.patch("arguss.web.routes.fetch_repo_inputs", side_effect=_mock_fetch_inputs),
        mock.patch("arguss.web.routes.propose_fixes") as mock_propose,
        mock.patch("arguss.web.routes.attach_executive_summary", side_effect=lambda p: p),
    ):
        mock_propose.return_value = ProposalReport(
            repo_path=str(tmp_path),
            lockfile_path=str(tmp_path / "package-lock.json"),
            entries=(),
            skipped_findings=(),
            summary=ProposalSummary(
                total_findings=1,
                total_candidates=0,
                auto_merge_count=0,
                review_required_count=0,
                decline_count=0,
                kev_count=0,
            ),
        )
        response = client.post(
            "/scan/url",
            json={"url": "https://github.com/lodash/lodash"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["kev_count"] == 0


def test_packages_sorted_kev_first() -> None:
    verdict = FixConfidence(
        candidate_id="x",
        tier=FixTier.REVIEW_REQUIRED,
        score=50,
        reasons=(),
        veto_signals=(),
        evaluated_at=datetime.now(UTC),
        engine_version="test",
    )
    base = FixCandidate(
        package="pkg",
        from_version="1.0.0",
        to_version="1.0.1",
        fix_kind=FixKind.PATCH,
        source_finding_ids=("GHSA-1",),
        repo_id="/tmp/repo",
    )

    kev_finding = _finding(package="kev-pkg", cve_id="CVE-KEV", is_kev=True)
    kev_entry = ProposalEntry(
        finding=kev_finding,
        related_findings=(kev_finding,),
        candidate=replace(base, package="kev-pkg", has_kev_finding=True),
        verdict=verdict,
    )
    high_finding = _finding(package="high-epss", epss_score=0.9)
    high_epss_entry = ProposalEntry(
        finding=high_finding,
        related_findings=(high_finding,),
        candidate=replace(
            _candidate_with_epss(base, [high_finding]),
            package="high-epss",
            max_epss_score=0.9,
        ),
        verdict=verdict,
    )
    plain_finding = _finding(package="plain")
    plain_entry = ProposalEntry(
        finding=plain_finding,
        related_findings=(plain_finding,),
        candidate=replace(base, package="plain"),
        verdict=verdict,
    )

    report = ProposalReport(
        repo_path="/tmp",
        lockfile_path="/tmp/package-lock.json",
        entries=(plain_entry, high_epss_entry, kev_entry),
        skipped_findings=(),
        summary=ProposalSummary(
            total_findings=3,
            total_candidates=3,
            auto_merge_count=0,
            review_required_count=3,
            decline_count=0,
        ),
    )

    groups = group_by_package(report)
    assert [g.name for g in groups] == ["kev-pkg", "high-epss", "plain"]
