"""Tests for GitHub PR title/body generation."""

from __future__ import annotations

from datetime import UTC, datetime

from arguss.core.models import Dependency, Finding, FixCandidate, FixConfidence, FixKind, FixTier
from arguss.engine.fix_confidence import ENGINE_VERSION
from arguss.web import github_action as ga

_FIXED_TIME = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)


def _finding(
    *,
    advisory_id: str,
    title: str,
    cvss_score: float | None = None,
    fixed_versions: tuple[str, ...] = ("3.36.0",),
    package: str = "simple-git",
    version: str = "3.28.0",
) -> Finding:
    return Finding(
        dependency=Dependency(name=package, version=version, direct=True),
        lens="cve",
        severity="critical" if cvss_score and cvss_score >= 9 else "high",
        score=90.0,
        cvss_score=cvss_score,
        title=title,
        description="test",
        advisory_id=advisory_id,
        fixed_versions=fixed_versions,
        source_url=f"https://osv.dev/vulnerability/{advisory_id}",
    )


def _candidate(
    *,
    source_finding_ids: tuple[str, ...] = ("GHSA-test",),
) -> FixCandidate:
    return FixCandidate(
        package="simple-git",
        from_version="3.28.0",
        to_version="3.36.0",
        fix_kind=FixKind.MINOR,
        source_finding_ids=source_finding_ids,
        repo_id="/tmp/repo",
    )


def _verdict(candidate: FixCandidate) -> FixConfidence:
    return FixConfidence(
        candidate_id=candidate.candidate_id,
        tier=FixTier.AUTO_MERGE,
        score=95,
        reasons=("minor-level upgrade; trust signals unchanged; CI verifies tests",),
        veto_signals=(),
        evaluated_at=_FIXED_TIME,
        engine_version=ENGINE_VERSION,
    )


def test_pr_description_single_finding_unchanged() -> None:
    finding = _finding(advisory_id="GHSA-test", title="GHSA-test: single issue")
    candidate = _candidate()
    body = ga._render_pr_body(candidate, _verdict(candidate), finding)
    assert "Fixes [GHSA-test]" in body
    assert "single issue" in body
    assert "Fixes 2 vulnerabilities" not in body


def test_pr_description_multi_finding_lists_all_cves() -> None:
    findings = (
        _finding(
            advisory_id="GHSA-hffm-xvc3-vprc",
            title="simple-git is vulnerable to Remote Code Execution",
            cvss_score=9.8,
            fixed_versions=("3.36.0",),
        ),
        _finding(
            advisory_id="GHSA-jcxm-m3jx-f287",
            title="simple-git Affected by Command Execution via Option-Parsing Bypass",
            cvss_score=8.1,
            fixed_versions=("3.32.0",),
        ),
        _finding(
            advisory_id="GHSA-r275-fr43-pm7q",
            title="blockUnsafeOperationsPlugin bypass via case-insensitive protocol.allow",
            cvss_score=9.8,
            fixed_versions=("3.32.3",),
        ),
    )
    candidate = _candidate(
        source_finding_ids=tuple(f.advisory_id or "" for f in findings),
    )
    body = ga._render_pr_body(
        candidate,
        _verdict(candidate),
        findings[0],
        related_findings=findings,
    )
    assert "Fixes 3 vulnerabilities in simple-git:" in body
    assert "GHSA-hffm-xvc3-vprc" in body
    assert "GHSA-jcxm-m3jx-f287" in body
    assert "GHSA-r275-fr43-pm7q" in body
    assert "consolidates fixes for 3 advisories" in body


def test_pr_description_multi_finding_sorted_by_severity() -> None:
    low = _finding(
        advisory_id="GHSA-low",
        title="low severity",
        cvss_score=4.0,
        fixed_versions=("3.30.0",),
    )
    high = _finding(
        advisory_id="GHSA-high",
        title="high severity",
        cvss_score=9.8,
        fixed_versions=("3.36.0",),
    )
    findings = (low, high)
    candidate = _candidate(source_finding_ids=("GHSA-low", "GHSA-high"))
    body = ga._render_pr_body(
        candidate,
        _verdict(candidate),
        low,
        related_findings=findings,
    )
    high_pos = body.index("GHSA-high")
    low_pos = body.index("GHSA-low")
    assert high_pos < low_pos


def test_pr_title_multi_finding_uses_consolidated_phrasing() -> None:
    findings = (
        _finding(advisory_id="GHSA-a", title="a", cvss_score=9.0),
        _finding(advisory_id="GHSA-b", title="b", cvss_score=8.0),
    )
    candidate = _candidate(source_finding_ids=("GHSA-a", "GHSA-b"))
    title = ga._pr_title(candidate, findings[0], related_findings=findings)
    assert title == "Arguss: upgrade simple-git 3.28.0 → 3.36.0 (resolves 2 CVEs)"


def test_pr_title_single_finding_unchanged() -> None:
    finding = _finding(advisory_id="GHSA-test", title="test")
    candidate = _candidate()
    title = ga._pr_title(candidate, finding)
    assert title == "Arguss: fix GHSA-test in simple-git"
