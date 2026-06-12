"""Tests for fix-candidate consolidation."""

from __future__ import annotations

import pytest

from arguss.core.models import Dependency, Finding, FixCandidate, FixKind
from arguss.engine.consolidate import consolidate_candidates


def _finding(
    *,
    advisory_id: str,
    package: str = "simple-git",
    version: str = "3.28.0",
    fixed_versions: tuple[str, ...] = ("3.36.0",),
    cvss_score: float | None = None,
    epss_score: float | None = None,
    is_kev: bool = False,
) -> Finding:
    return Finding(
        dependency=Dependency(name=package, version=version, direct=True),
        lens="cve",
        severity="high",
        score=75.0,
        cvss_score=cvss_score,
        title=f"{advisory_id}: vulnerability in {package}",
        description="test",
        advisory_id=advisory_id,
        fixed_versions=fixed_versions,
        epss_score=epss_score,
        is_kev=is_kev,
    )


def _candidate_ids(*findings: Finding) -> tuple[str, ...]:
    return tuple(f.finding_id for f in findings)


def _candidate(
    *,
    package: str = "simple-git",
    from_version: str = "3.28.0",
    to_version: str = "3.36.0",
    fix_kind: FixKind = FixKind.MINOR,
    source_finding_ids: tuple[str, ...] = ("GHSA-a",),
    max_epss_score: float | None = None,
    max_epss_percentile: float | None = None,
    has_kev_finding: bool = False,
) -> FixCandidate:
    return FixCandidate(
        package=package,
        from_version=from_version,
        to_version=to_version,
        fix_kind=fix_kind,
        source_finding_ids=source_finding_ids,
        repo_id="/tmp/repo",
        max_epss_score=max_epss_score,
        max_epss_percentile=max_epss_percentile,
        has_kev_finding=has_kev_finding,
    )


def test_single_candidate_passes_through_unchanged() -> None:
    candidate = _candidate(source_finding_ids=("GHSA-only",))
    findings = [_finding(advisory_id="GHSA-only")]
    result = consolidate_candidates([candidate], findings)
    assert len(result) == 1
    assert result[0].source_finding_ids == ("GHSA-only",)
    assert result[0].to_version == "3.36.0"


def test_two_candidates_same_package_consolidated_to_higher_target() -> None:
    a = _candidate(to_version="3.32.0", source_finding_ids=("GHSA-a",))
    b = _candidate(to_version="3.36.0", source_finding_ids=("GHSA-b",))
    findings = [
        _finding(advisory_id="GHSA-a", fixed_versions=("3.32.0",)),
        _finding(advisory_id="GHSA-b", fixed_versions=("3.36.0",)),
    ]
    result = consolidate_candidates([a, b], findings)
    assert len(result) == 1
    assert result[0].to_version == "3.36.0"
    assert result[0].source_finding_ids == ("GHSA-a", "GHSA-b")


def test_three_candidates_same_package_picks_max() -> None:
    candidates = [
        _candidate(to_version="3.32.0", source_finding_ids=("GHSA-a",)),
        _candidate(to_version="3.32.3", source_finding_ids=("GHSA-b",)),
        _candidate(to_version="3.36.0", source_finding_ids=("GHSA-c",)),
    ]
    findings = [
        _finding(advisory_id="GHSA-a", fixed_versions=("3.32.0",)),
        _finding(advisory_id="GHSA-b", fixed_versions=("3.32.3",)),
        _finding(advisory_id="GHSA-c", fixed_versions=("3.36.0",)),
    ]
    result = consolidate_candidates(candidates, findings)
    assert len(result) == 1
    assert result[0].to_version == "3.36.0"
    assert len(result[0].source_finding_ids) == 3


def test_consolidation_recomputes_fix_kind_when_escalating() -> None:
    a = _candidate(to_version="3.32.0", fix_kind=FixKind.MINOR, source_finding_ids=("GHSA-a",))
    b = _candidate(to_version="4.0.0", fix_kind=FixKind.MAJOR, source_finding_ids=("GHSA-b",))
    findings = [
        _finding(advisory_id="GHSA-a", fixed_versions=("3.32.0",)),
        _finding(advisory_id="GHSA-b", fixed_versions=("4.0.0",)),
    ]
    result = consolidate_candidates([a, b], findings)
    assert len(result) == 1
    assert result[0].to_version == "4.0.0"
    assert result[0].fix_kind is FixKind.MAJOR


def test_consolidation_aggregates_max_epss() -> None:
    a = _candidate(
        to_version="3.32.0",
        source_finding_ids=("GHSA-a",),
        max_epss_score=0.001,
    )
    b = _candidate(
        to_version="3.36.0",
        source_finding_ids=("GHSA-b",),
        max_epss_score=0.05,
    )
    findings = [
        _finding(advisory_id="GHSA-a", fixed_versions=("3.32.0",)),
        _finding(advisory_id="GHSA-b", fixed_versions=("3.36.0",)),
    ]
    result = consolidate_candidates([a, b], findings)
    assert result[0].max_epss_score == 0.05


def test_consolidation_any_kev_propagates() -> None:
    a = _candidate(to_version="3.32.0", source_finding_ids=("GHSA-a",), has_kev_finding=False)
    b = _candidate(to_version="3.36.0", source_finding_ids=("GHSA-b",), has_kev_finding=True)
    findings = [
        _finding(advisory_id="GHSA-a", fixed_versions=("3.32.0",)),
        _finding(advisory_id="GHSA-b", fixed_versions=("3.36.0",), is_kev=True),
    ]
    result = consolidate_candidates([a, b], findings)
    assert result[0].has_kev_finding is True


def test_consolidation_handles_none_epss_gracefully() -> None:
    a = _candidate(
        to_version="3.32.0",
        source_finding_ids=("GHSA-a",),
        max_epss_score=None,
    )
    b = _candidate(
        to_version="3.36.0",
        source_finding_ids=("GHSA-b",),
        max_epss_score=0.1,
    )
    findings = [
        _finding(advisory_id="GHSA-a", fixed_versions=("3.32.0",)),
        _finding(advisory_id="GHSA-b", fixed_versions=("3.36.0",)),
    ]
    result = consolidate_candidates([a, b], findings)
    assert result[0].max_epss_score == 0.1


def test_multiple_packages_consolidated_independently() -> None:
    pkg_a_1 = _candidate(
        package="pkg-a",
        from_version="1.0.0",
        to_version="1.1.0",
        source_finding_ids=("GHSA-a1",),
    )
    pkg_a_2 = _candidate(
        package="pkg-a",
        from_version="1.0.0",
        to_version="1.2.0",
        source_finding_ids=("GHSA-a2",),
    )
    pkg_b_1 = _candidate(
        package="pkg-b",
        from_version="1.0.0",
        to_version="2.1.0",
        source_finding_ids=("GHSA-b1",),
    )
    pkg_b_2 = _candidate(
        package="pkg-b",
        from_version="1.0.0",
        to_version="2.2.0",
        source_finding_ids=("GHSA-b2",),
    )
    findings = [
        _finding(
            advisory_id="GHSA-a1", package="pkg-a", version="1.0.0", fixed_versions=("1.1.0",)
        ),
        _finding(
            advisory_id="GHSA-a2", package="pkg-a", version="1.0.0", fixed_versions=("1.2.0",)
        ),
        _finding(
            advisory_id="GHSA-b1", package="pkg-b", version="1.0.0", fixed_versions=("2.1.0",)
        ),
        _finding(
            advisory_id="GHSA-b2", package="pkg-b", version="1.0.0", fixed_versions=("2.2.0",)
        ),
    ]
    result = consolidate_candidates([pkg_a_1, pkg_a_2, pkg_b_1, pkg_b_2], findings)
    assert len(result) == 2
    by_pkg = {c.package: c for c in result}
    assert by_pkg["pkg-a"].to_version == "1.2.0"
    assert by_pkg["pkg-b"].to_version == "2.2.0"


def test_consolidation_is_deterministic() -> None:
    a = _candidate(to_version="3.32.0", source_finding_ids=("GHSA-a",))
    b = _candidate(to_version="3.36.0", source_finding_ids=("GHSA-b",))
    findings = [
        _finding(advisory_id="GHSA-a", fixed_versions=("3.32.0",)),
        _finding(advisory_id="GHSA-b", fixed_versions=("3.36.0",)),
    ]
    first = consolidate_candidates([a, b], findings)
    second = consolidate_candidates([b, a], findings)
    assert first == second


def test_consolidated_source_finding_ids_sorted_and_deduped() -> None:
    shared = ("GHSA-shared",)
    candidates = [
        _candidate(to_version="3.32.0", source_finding_ids=shared + ("GHSA-a",)),
        _candidate(to_version="3.36.0", source_finding_ids=shared + ("GHSA-b",)),
        _candidate(to_version="3.36.0", source_finding_ids=("GHSA-c",)),
    ]
    findings = [
        _finding(advisory_id="GHSA-shared", fixed_versions=("3.30.0",)),
        _finding(advisory_id="GHSA-a", fixed_versions=("3.32.0",)),
        _finding(advisory_id="GHSA-b", fixed_versions=("3.36.0",)),
        _finding(advisory_id="GHSA-c", fixed_versions=("3.36.0",)),
    ]
    result = consolidate_candidates(candidates, findings)
    assert result[0].source_finding_ids == ("GHSA-a", "GHSA-b", "GHSA-c", "GHSA-shared")


def test_disjoint_fix_versions_falls_back_to_per_finding(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When max target cannot satisfy all findings, emit per-finding candidates."""
    fa = _finding(
        advisory_id="GHSA-a",
        package="weird-pkg",
        version="1.0.0",
        fixed_versions=("3.0.0",),
    )
    fb = _finding(
        advisory_id="GHSA-b",
        package="weird-pkg",
        version="1.0.0",
        fixed_versions=("4.0.0",),
    )
    findings = [fa, fb]
    a = _candidate(
        package="weird-pkg",
        from_version="1.0.0",
        to_version="3.0.0",
        fix_kind=FixKind.MAJOR,
        source_finding_ids=(fa.finding_id,),
    )
    b = _candidate(
        package="weird-pkg",
        from_version="1.0.0",
        to_version="2.0.0",
        fix_kind=FixKind.MAJOR,
        source_finding_ids=(fb.finding_id,),
    )
    with caplog.at_level("WARNING"):
        result = consolidate_candidates([a, b], findings)
    assert len(result) == 2
    assert "falling back to per-finding candidates" in caplog.text
