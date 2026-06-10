"""Integration tests for EPSS enrichment across lens, propose, and dashboard."""

from __future__ import annotations

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
    _compute_epss_summary,
)
from arguss.lenses._epss_client import EpssData
from arguss.lenses.vulnerability import VulnerabilityLens, _enrich_findings_with_epss
from arguss.scoring.unified import epss_urgency_tier
from arguss.web.dashboard import _sort_entries_by_epss


def _finding(
    *,
    package: str = "lodash",
    epss_score: float | None = None,
    cve_id: str | None = "CVE-2024-0001",
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
    )


def test_finding_populated_with_epss() -> None:
    findings = [
        _finding(epss_score=None, cve_id="CVE-2024-0001"),
        _finding(epss_score=None, cve_id="CVE-2024-0002", package="axios"),
    ]

    async def fake_fetch(
        cve_ids: object,
        *,
        cache: object = None,
        http_client: object = None,
        api_base: str = "",
    ) -> dict[str, EpssData]:
        return {
            "CVE-2024-0001": EpssData("CVE-2024-0001", 0.21, 0.8, "2024-01-01"),
            "CVE-2024-0002": EpssData("CVE-2024-0002", 0.05, 0.3, "2024-01-01"),
        }

    with mock.patch(
        "arguss.lenses.vulnerability.fetch_epss_for_cves",
        side_effect=fake_fetch,
    ):
        enriched = _enrich_findings_with_epss(findings, mock.MagicMock())

    assert enriched[0].epss_score == 0.21
    assert enriched[0].epss_percentile == 0.8
    assert enriched[0].cve_id == "CVE-2024-0001"
    assert enriched[1].epss_score == 0.05


def test_candidate_max_epss_picks_highest() -> None:
    base = FixCandidate(
        package="pkg",
        from_version="1.0.0",
        to_version="1.0.1",
        fix_kind=FixKind.PATCH,
        source_finding_ids=("GHSA-1",),
        repo_id="/tmp/repo",
    )
    c_high = _candidate_with_epss(base, [_finding(epss_score=0.5)])
    c_low = _candidate_with_epss(base, [_finding(epss_score=0.1)])
    c_mid = _candidate_with_epss(base, [_finding(epss_score=0.05)])

    assert c_high.max_epss_score == 0.5
    assert c_low.max_epss_score == 0.1
    assert c_mid.max_epss_score == 0.05


def test_summary_max_epss_picks_global_highest() -> None:
    findings = [
        _finding(epss_score=0.1, package="a"),
        _finding(epss_score=0.5, package="b", cve_id="CVE-2024-9999"),
        _finding(epss_score=0.05, package="c"),
    ]
    score, cve, pkg = _compute_epss_summary(findings)
    assert score == 0.5
    assert cve == "CVE-2024-9999"
    assert pkg == "b"


def test_summary_max_epss_none_when_no_epss_data() -> None:
    findings = [_finding(epss_score=None, cve_id=None)]
    assert _compute_epss_summary(findings) == (None, None, None)


@pytest.mark.parametrize(
    ("score", "tier"),
    [
        (None, None),
        (0.50, "critical"),
        (0.49, "high"),
        (0.10, "high"),
        (0.09, "medium"),
        (0.01, "medium"),
        (0.009, "low"),
    ],
)
def test_epss_urgency_tier_thresholds(score: float | None, tier: str | None) -> None:
    assert epss_urgency_tier(score) == tier


def test_findings_sorted_by_epss_within_package() -> None:
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

    def _entry(epss_score: float | None) -> ProposalEntry:
        finding = _finding(epss_score=epss_score)
        return ProposalEntry(
            finding=finding,
            related_findings=(finding,),
            candidate=_candidate_with_epss(base, [finding]),
            verdict=verdict,
        )

    entries = [_entry(0.3), _entry(None), _entry(0.7), _entry(0.1)]
    sorted_entries = _sort_entries_by_epss(entries)
    scores = [e.candidate.max_epss_score for e in sorted_entries]
    assert scores == [0.7, 0.3, 0.1, None]


async def _mock_fetch_inputs(owner: str, repo: str, ref: str, dest: Path) -> object:
    from arguss.web.github_fetch import RepoInputs

    dest.mkdir(parents=True, exist_ok=True)
    lockfile = dest / "package-lock.json"
    lockfile.write_text(
        '{"lockfileVersion": 3, "packages": {"": {"name": "t", "version": "1.0.0"}}}',
        encoding="utf-8",
    )
    return RepoInputs(work_tree=dest, lockfile_path=lockfile)


def test_scan_completes_when_epss_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from arguss.core.cache import Cache, get_connection, init_db
    from arguss.core.models import LensScore

    async def empty_epss(*args: object, **kwargs: object) -> dict[str, EpssData]:
        return {}

    monkeypatch.setattr(
        "arguss.lenses.vulnerability.fetch_epss_for_cves",
        empty_epss,
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
    assert result.findings[0].epss_score is None
    assert result.findings[0].cve_id == "CVE-2024-0001"

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
            ),
        )
        response = client.post(
            "/scan/url",
            json={"url": "https://github.com/lodash/lodash"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["max_epss_score"] is None
