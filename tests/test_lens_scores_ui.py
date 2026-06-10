"""Tests for lens score surfacing (PRS, subscores, CVSS, trust per package)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from arguss.core.models import (
    Dependency,
    Finding,
    LensScore,
    PipelineSnapshot,
    TestReality,
)
from arguss.engine.project_scores import build_project_scores
from arguss.lenses.vulnerability import _vuln_to_finding
from arguss.scoring.unified import compute_prs
from arguss.web import dashboard as dashboard_mod

FIXTURES = __import__("pathlib").Path(__file__).parent / "fixtures" / "lockfiles"


def _pipeline(subscore: int = 40) -> PipelineSnapshot:
    tr = TestReality(
        has_test_script=True,
        test_script_is_no_op=False,
        has_test_files=True,
        test_count=1,
        workflow_runs_tests=True,
        safe_to_auto_merge=True,
        reasons_blocked=(),
    )
    return PipelineSnapshot(
        repo_path="/repo",
        workflow_files=(),
        zizmor_findings=(),
        test_reality=tr,
        subscore=subscore,
    )


def test_compute_prs_weights() -> None:
    assert compute_prs(100, 100, 100) == 100
    assert compute_prs(50, 50, 50) == 50
    assert compute_prs(80, 60, 40) == round(0.4 * 80 + 0.3 * 60 + 0.3 * 40)


def test_compute_prs_returns_none_with_missing_input() -> None:
    assert compute_prs(None, 50, 50) is None
    assert compute_prs(50, None, 50) is None
    assert compute_prs(50, 50, None) is None


def test_project_scores_populated_when_all_lenses_succeed() -> None:
    cve = LensScore(lens="cve", score=80.0)
    trust = LensScore(lens="trust", score=60.0)
    pipeline = _pipeline(subscore=40)
    scores = build_project_scores(cve, trust, pipeline)
    assert scores is not None
    assert scores.vulnerability_subscore == 80
    assert scores.trust_subscore == 60
    assert scores.pipeline_subscore == 40
    assert scores.prs == compute_prs(80, 60, 40)


def test_project_scores_none_when_build_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    cve = LensScore(lens="cve", score=80.0)
    trust = LensScore(lens="trust", score=60.0)
    pipeline = _pipeline(subscore=40)

    def _boom(*_a: object, **_k: object) -> int:
        raise RuntimeError("boom")

    monkeypatch.setattr("arguss.engine.project_scores.compute_prs", _boom)
    assert build_project_scores(cve, trust, pipeline) is None


def test_per_package_trust_subscore_propagates(tmp_path: Path) -> None:
    from arguss.core.models import FixCandidate, FixConfidence, FixKind, FixTier
    from arguss.engine.fix_confidence import ENGINE_VERSION
    from arguss.engine.propose import ProposalEntry, ProposalReport, ProposalSummary

    candidate = FixCandidate(
        package="lodash",
        from_version="1.0.0",
        to_version="1.0.1",
        fix_kind=FixKind.PATCH,
        source_finding_ids=("GHSA-x",),
        repo_id="/repo",
        trust_subscore=42,
    )
    finding = Finding(
        dependency=Dependency(name="lodash", version="1.0.0", direct=True),
        lens="cve",
        severity="high",
        score=75.0,
        title="test",
        description="test",
    )
    verdict = FixConfidence(
        candidate_id=candidate.candidate_id,
        tier=FixTier.REVIEW_REQUIRED,
        score=50,
        reasons=(),
        veto_signals=(),
        evaluated_at=datetime.now(UTC),
        engine_version=ENGINE_VERSION,
    )
    report = ProposalReport(
        repo_path="/repo",
        lockfile_path="/repo/package-lock.json",
        entries=(
            ProposalEntry(
                finding=finding, related_findings=(finding,), candidate=candidate, verdict=verdict
            ),
        ),
        skipped_findings=(),
        summary=ProposalSummary(1, 1, 0, 1, 0),
    )
    groups = dashboard_mod.group_by_package(report)
    assert len(groups) == 1
    assert groups[0].trust_subscore == 42


def test_per_finding_cvss_score_populated() -> None:
    dep = Dependency(name="pkg", version="1.0.0", direct=True)
    vuln = {
        "id": "GHSA-test",
        "summary": "test",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
    }
    finding = _vuln_to_finding(vuln, dep)
    assert finding.cvss_score == 7.5
