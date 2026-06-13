"""Tests for scan_counts balance and finalize_scan_payload wiring."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import pytest

from arguss.core.models import (
    Dependency,
    Finding,
    FixCandidate,
    FixConfidence,
    FixKind,
    FixTier,
    NoFixSkip,
)
from arguss.core.serialization import finalize_scan_payload, proposal_report_payload
from arguss.engine.fix_confidence import ENGINE_VERSION
from arguss.engine.propose import ProposalEntry, ProposalReport, ProposalSummary
from arguss.engine.scan_counts import ScanCounts, build_scan_counts, scan_counts_to_dict
from arguss.explanations.scan_cache import cache_scan_response, get_cached_scan_response
from arguss.settings import settings
from arguss.web.results_context import build_packages

_REPO = "/tmp/arguss-scan-counts-repo"
_FIXED_TIME = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)


def _finding(
    *,
    advisory_id: str,
    package: str = "simple-git",
    version: str = "3.28.0",
    severity: str = "high",
    epss_score: float | None = None,
    path: list[str] | None = None,
) -> Finding:
    return Finding(
        dependency=Dependency(
            name=package,
            version=version,
            direct=True,
            path=path or ["node_modules", package],
        ),
        lens="cve",
        severity=severity,
        score=75.0,
        title=f"{advisory_id}: vulnerability in {package}",
        description="test",
        advisory_id=advisory_id,
        fixed_versions=("99.0.0",),
        epss_score=epss_score,
    )


def _candidate(
    *,
    package: str,
    from_version: str,
    to_version: str,
    source_findings: tuple[Finding, ...],
    fix_kind: FixKind = FixKind.MINOR,
) -> FixCandidate:
    return FixCandidate(
        package=package,
        from_version=from_version,
        to_version=to_version,
        fix_kind=fix_kind,
        source_finding_ids=tuple(f.finding_id for f in source_findings),
        repo_id=_REPO,
    )


def _verdict(candidate: FixCandidate, *, tier: FixTier = FixTier.AUTO_MERGE) -> FixConfidence:
    return FixConfidence(
        candidate_id=candidate.candidate_id,
        tier=tier,
        score=80,
        reasons=("test",),
        veto_signals=(),
        evaluated_at=_FIXED_TIME,
        engine_version=ENGINE_VERSION,
    )


def _entry(
    findings: tuple[Finding, ...],
    *,
    package: str | None = None,
    from_version: str | None = None,
    to_version: str = "99.0.0",
    tier: FixTier = FixTier.AUTO_MERGE,
) -> ProposalEntry:
    assert findings
    pkg = package or findings[0].dependency.name
    fv = from_version or findings[0].dependency.version
    cand = _candidate(
        package=pkg,
        from_version=fv,
        to_version=to_version,
        source_findings=findings,
    )
    return ProposalEntry(
        finding=findings[0],
        related_findings=findings,
        candidate=cand,
        verdict=_verdict(cand, tier=tier),
    )


def _report(
    *,
    entries: tuple[ProposalEntry, ...],
    findings_snapshot: tuple[Finding, ...],
    skipped: tuple = (),
) -> ProposalReport:
    tier_counts = {FixTier.AUTO_MERGE: 0, FixTier.REVIEW_REQUIRED: 0, FixTier.DECLINE: 0}
    for entry in entries:
        tier_counts[entry.verdict.tier] += 1
    return ProposalReport(
        repo_path=_REPO,
        lockfile_path="/tmp/package-lock.json",
        entries=entries,
        skipped_findings=skipped,
        summary=ProposalSummary(
            total_findings=len(findings_snapshot),
            total_candidates=len(entries),
            auto_merge_count=tier_counts[FixTier.AUTO_MERGE],
            review_required_count=tier_counts[FixTier.REVIEW_REQUIRED],
            decline_count=tier_counts[FixTier.DECLINE],
        ),
        findings_snapshot=findings_snapshot,
    )


def _deps(*pairs: tuple[str, str]) -> list[dict[str, str]]:
    return [{"package": p, "version": v} for p, v in pairs]


def test_simple_git_shape_three_findings_one_candidate_rollup_balance_ok() -> None:
    findings = tuple(
        _finding(advisory_id=f"GHSA-sg-{i}", package="simple-git", version="3.28.0")
        for i in range(3)
    )
    report = _report(entries=(_entry(findings),), findings_snapshot=findings)
    deps = _deps(("simple-git", "3.28.0"), ("chalk", "5.0.0"))
    counts = build_scan_counts(report, deps)

    assert counts.total_findings == 3
    assert counts.total_candidates == 1
    assert counts.balance.ok is True
    rollup = next(r for r in counts.package_rollups if r.package == "simple-git")
    assert rollup.finding_count == 3
    assert len(rollup.finding_ids) == 3


def test_minimatch_shape_partitions_findings_per_from_version() -> None:
    f1 = (_finding(advisory_id="GHSA-mm-1", package="minimatch", version="9.0.3"),)
    f2 = (
        _finding(advisory_id="GHSA-mm-2a", package="minimatch", version="9.0.5"),
        _finding(advisory_id="GHSA-mm-2b", package="minimatch", version="9.0.5"),
    )
    f3 = (_finding(advisory_id="GHSA-mm-3", package="minimatch", version="9.0.7"),)
    entries = (
        _entry(f1, from_version="9.0.3", to_version="9.0.4"),
        _entry(f2, from_version="9.0.5", to_version="9.0.6"),
        _entry(f3, from_version="9.0.7", to_version="9.0.8"),
    )
    snapshot = f1 + f2 + f3
    report = _report(entries=entries, findings_snapshot=snapshot)
    counts = build_scan_counts(
        report,
        _deps(
            ("minimatch", "9.0.3"),
            ("minimatch", "9.0.5"),
            ("minimatch", "9.0.7"),
        ),
    )

    assert counts.total_findings == 4
    assert counts.total_candidates == 3
    assert counts.balance.ok is True
    by_cid = {c.candidate_id: set(c.related_finding_ids) for c in counts.candidates}
    all_ids: set[str] = set()
    for related in by_cid.values():
        assert not (related & all_ids)
        all_ids |= related
    assert len(all_ids) == 4
    assert [len(c.related_finding_ids) for c in counts.candidates] == [1, 2, 1]


def test_tar_regression_max_epss_ignores_none() -> None:
    findings = (
        _finding(advisory_id="GHSA-tar-a", package="tar", version="6.2.0", epss_score=0.85),
        _finding(advisory_id="GHSA-tar-b", package="tar", version="6.2.0", epss_score=None),
    )
    report = _report(entries=(_entry(findings),), findings_snapshot=findings)
    counts = build_scan_counts(report, _deps(("tar", "6.2.0")))

    assert counts.candidates[0].aggregates.max_epss_score == 0.85
    assert counts.balance.ok is True


def test_severity_counts_sum_to_total_findings() -> None:
    findings = (
        _finding(advisory_id="GHSA-crit", severity="critical"),
        _finding(advisory_id="GHSA-high", severity="high"),
        _finding(advisory_id="GHSA-med", severity="medium"),
        _finding(advisory_id="GHSA-low", severity="low"),
    )
    report = _report(entries=(_entry(findings),), findings_snapshot=findings)
    counts = build_scan_counts(report, _deps(("simple-git", "3.28.0")))

    assert sum(counts.findings_by_severity.values()) == counts.total_findings
    assert counts.balance.ok is True


def test_tier_counts_sum_to_total_candidates() -> None:
    f_auto = (_finding(advisory_id="GHSA-am"),)
    f_review = (_finding(advisory_id="GHSA-rr", package="pkg-b", version="1.0.0"),)
    f_decline = (_finding(advisory_id="GHSA-dc", package="pkg-c", version="1.0.0"),)
    entries = (
        _entry(f_auto, tier=FixTier.AUTO_MERGE),
        _entry(f_review, package="pkg-b", from_version="1.0.0", tier=FixTier.REVIEW_REQUIRED),
        _entry(f_decline, package="pkg-c", from_version="1.0.0", tier=FixTier.DECLINE),
    )
    snapshot = f_auto + f_review + f_decline
    report = _report(entries=entries, findings_snapshot=snapshot)
    counts = build_scan_counts(
        report,
        _deps(("simple-git", "3.28.0"), ("pkg-b", "1.0.0"), ("pkg-c", "1.0.0")),
    )

    tier_sum = (
        counts.candidates_auto_merge
        + counts.candidates_review_required
        + counts.candidates_decline
        + counts.candidates_unknown_tier
    )
    assert tier_sum == counts.total_candidates
    assert counts.balance.ok is True


def test_node_partition_clean_plus_affected_equals_node_count() -> None:
    findings = (_finding(advisory_id="GHSA-affected", package="simple-git", version="3.28.0"),)
    report = _report(entries=(_entry(findings),), findings_snapshot=findings)
    deps = _deps(("simple-git", "3.28.0"), ("left-pad", "1.3.0"), ("chalk", "5.0.0"))
    counts = build_scan_counts(report, deps)

    assert counts.clean_node_count + counts.affected_node_count == counts.node_count
    assert counts.balance.ok is True


def test_build_scan_counts_dict_is_deterministic() -> None:
    findings = tuple(
        _finding(advisory_id=f"GHSA-det-{i}", package="simple-git", version="3.28.0")
        for i in range(2)
    )
    report = _report(entries=(_entry(findings),), findings_snapshot=findings)
    deps = _deps(("simple-git", "3.28.0"))
    counts = build_scan_counts(report, deps)
    first = scan_counts_to_dict(counts)
    second = scan_counts_to_dict(counts)
    assert first == second


def test_finalize_scan_payload_scan_counts_matches_direct_build(tmp_path: Path) -> None:
    findings = tuple(
        _finding(advisory_id=f"GHSA-fin-{i}", package="left-pad", version="1.3.0") for i in range(2)
    )
    report = _report(entries=(_entry(findings),), findings_snapshot=findings)
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        '{"lockfileVersion":3,"packages":{"":{"name":"t","version":"1.0.0"},'
        '"node_modules/left-pad":{"version":"1.3.0"}}}'
    )
    payload = finalize_scan_payload(report, lockfile)
    direct = scan_counts_to_dict(build_scan_counts(report, payload["deps"]))
    assert payload["scan_counts"] == direct


def test_finalize_scan_payload_twice_is_identical(tmp_path: Path) -> None:
    findings = (_finding(advisory_id="GHSA-twice", package="left-pad", version="1.3.0"),)
    report = _report(entries=(_entry(findings),), findings_snapshot=findings)
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        '{"lockfileVersion":3,"packages":{"":{"name":"t","version":"1.0.0"},'
        '"node_modules/left-pad":{"version":"1.3.0"}}}'
    )
    first = finalize_scan_payload(report, lockfile)
    second = finalize_scan_payload(report, lockfile)
    assert first == second


def _assert_scan_identities(counts: ScanCounts) -> None:
    assert counts.total_findings == counts.findings_with_fix + counts.findings_no_fix
    assert sum(counts.findings_by_severity.values()) == counts.total_findings
    tier_sum = (
        counts.candidates_auto_merge
        + counts.candidates_review_required
        + counts.candidates_decline
        + counts.candidates_unknown_tier
    )
    assert tier_sum == counts.total_candidates
    assert counts.clean_node_count + counts.affected_node_count == counts.node_count
    all_related: set[str] = set()
    for candidate in counts.candidates:
        related = set(candidate.related_finding_ids)
        assert not (related & all_related)
        all_related |= related
    assert len(all_related) == counts.findings_with_fix
    assert sum(len(c.related_finding_ids) for c in counts.candidates) == counts.findings_with_fix


def test_multi_install_path_same_advisory_two_findings_one_advisory_card() -> None:
    advisory = "GHSA-multi-path"
    findings = (
        _finding(advisory_id=advisory, package="lodash", version="4.17.20", path=["root", "a"]),
        _finding(advisory_id=advisory, package="lodash", version="4.17.20", path=["root", "b"]),
    )
    report = _report(entries=(_entry(findings),), findings_snapshot=findings)
    deps = _deps(("lodash", "4.17.20"))
    counts = build_scan_counts(report, deps)

    assert counts.total_findings == 2
    rollup = next(r for r in counts.package_rollups if r.package == "lodash")
    assert rollup.finding_count == 2
    _assert_scan_identities(counts)

    cached = proposal_report_payload(report)
    cached["deps"] = deps
    cached["scan_counts"] = scan_counts_to_dict(counts)
    packages = build_packages(cached)
    lodash = next(p for p in packages if p.name == "lodash")
    assert lodash.total_count == 2
    assert len(lodash.advisory_findings) == 1
    assert lodash.advisory_findings[0].install_path_count == 2
    assert lodash.advisory_findings[0].advisory_id == advisory


def test_all_identities_hold_on_minimatch_fixture() -> None:
    f1 = (_finding(advisory_id="GHSA-mm-1", package="minimatch", version="9.0.3"),)
    f2 = (
        _finding(advisory_id="GHSA-mm-2a", package="minimatch", version="9.0.5"),
        _finding(advisory_id="GHSA-mm-2b", package="minimatch", version="9.0.5"),
    )
    f3 = (_finding(advisory_id="GHSA-mm-3", package="minimatch", version="9.0.7"),)
    entries = (
        _entry(f1, from_version="9.0.3", to_version="9.0.4"),
        _entry(f2, from_version="9.0.5", to_version="9.0.6"),
        _entry(f3, from_version="9.0.7", to_version="9.0.8"),
    )
    snapshot = f1 + f2 + f3
    report = _report(entries=entries, findings_snapshot=snapshot)
    counts = build_scan_counts(
        report,
        _deps(
            ("minimatch", "9.0.3"),
            ("minimatch", "9.0.5"),
            ("minimatch", "9.0.7"),
        ),
    )
    _assert_scan_identities(counts)
    assert counts.balance.ok is True


def test_tar_all_findings_lack_epss_aggregate_is_none() -> None:
    findings = (
        _finding(advisory_id="GHSA-tar-a", package="tar", version="6.2.0", epss_score=None),
        _finding(advisory_id="GHSA-tar-b", package="tar", version="6.2.0", epss_score=None),
    )
    report = _report(entries=(_entry(findings),), findings_snapshot=findings)
    counts = build_scan_counts(report, _deps(("tar", "6.2.0")))

    assert counts.candidates[0].aggregates.max_epss_score is None


def test_balance_failure_logs_scan_hash_and_identity(caplog: pytest.LogCaptureFixture) -> None:
    findings = (_finding(advisory_id="GHSA-empty-related"),)
    cand = _candidate(
        package="simple-git",
        from_version="3.28.0",
        to_version="99.0.0",
        source_findings=findings,
    )
    broken_entry = ProposalEntry(
        finding=findings[0],
        related_findings=(),
        candidate=cand,
        verdict=_verdict(cand),
    )
    report = _report(entries=(broken_entry,), findings_snapshot=findings)
    caplog.set_level(logging.WARNING, logger="arguss.engine.scan_counts")
    counts = build_scan_counts(report, _deps(("simple-git", "3.28.0")), scan_hash="broken-hash-001")

    assert counts.balance.ok is False
    warnings = [
        r
        for r in caplog.records
        if r.getMessage() == ("scan balance failed scan_hash=%s identity=%s messages=%s")
        or "scan balance failed" in r.getMessage()
    ]
    assert len(warnings) == 1
    msg = warnings[0].getMessage()
    assert "broken-hash-001" in msg
    assert "candidate_empty_related" in msg
    assert any(m.startswith("candidate_empty_related") for m in counts.balance.messages)
    assert "findings_no_fix_skip_count" in counts.balance.messages
    assert warnings[0].args[1] == "findings_no_fix_skip_count"


def test_scan_counts_identical_after_cache_round_trip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "scan-cache.sqlite"
    monkeypatch.setattr(settings, "db_path", db_path)

    findings = tuple(
        _finding(advisory_id=f"GHSA-cache-{i}", package="left-pad", version="1.3.0")
        for i in range(2)
    )
    report = _report(entries=(_entry(findings),), findings_snapshot=findings)
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        '{"lockfileVersion":3,"packages":{"":{"name":"t","version":"1.0.0"},'
        '"node_modules/left-pad":{"version":"1.3.0"}}}'
    )
    payload = finalize_scan_payload(report, lockfile)
    original = payload["scan_counts"]

    scan_hash = cache_scan_response(payload)
    loaded = get_cached_scan_response(scan_hash)
    assert loaded is not None
    assert json.loads(json.dumps(original)) == loaded["scan_counts"]

    rebuilt = scan_counts_to_dict(build_scan_counts(report, loaded["deps"]))
    assert rebuilt == original


def test_build_packages_raises_without_package_rollups() -> None:
    from arguss.web.results_context import ScanCountsRollupError, build_packages

    payload = {
        "entries": [
            {
                "finding": {"severity": "high"},
                "candidate": {"package": "lodash", "candidate_id": "c1"},
                "verdict": {"tier": "auto_merge"},
            }
        ],
    }
    with pytest.raises(ScanCountsRollupError):
        build_packages(payload, scan_hash="no-rollups")


def test_findings_no_fix_matches_no_fix_skip_count() -> None:
    with_fix = _finding(advisory_id="GHSA-with-fix")
    orphan = _finding(advisory_id="GHSA-orphan-no-skip")
    report = _report(
        entries=(_entry((with_fix,)),),
        findings_snapshot=(with_fix, orphan),
    )
    counts = build_scan_counts(report, _deps(("simple-git", "3.28.0")))

    assert counts.findings_no_fix == 1
    assert counts.balance.ok is False
    assert "findings_no_fix_skip_count" in counts.balance.messages


def test_findings_no_fix_skip_count_holds_when_skips_present() -> None:
    with_fix = _finding(advisory_id="GHSA-with-fix-2")
    no_fix = _finding(advisory_id="GHSA-no-fix-2").model_copy(update={"fixed_versions": ()})
    skip = NoFixSkip(
        finding_id=no_fix.finding_id,
        advisory_id=no_fix.advisory_id or "",
        package=no_fix.dependency.name,
        current_version=no_fix.dependency.version,
        title=no_fix.title,
        description=no_fix.description,
        reason="no_fix_version_in_osv",
    )
    report = _report(
        entries=(_entry((with_fix,)),),
        findings_snapshot=(with_fix, no_fix),
        skipped=(skip,),
    )
    counts = build_scan_counts(report, _deps(("simple-git", "3.28.0")))

    assert counts.findings_no_fix == 1
    assert counts.balance.ok is True


def test_package_status_mixed_no_fix_partition() -> None:
    with_fix = _finding(advisory_id="GHSA-with-fix", package="chalk", version="4.1.2")
    chalk_no_fix = _finding(advisory_id="GHSA-chalk-nofix", package="chalk", version="4.1.2")
    exclusive_finding = _finding(advisory_id="GHSA-exclusive", package="left-pad", version="1.3.0")
    mixed_skip = NoFixSkip(
        finding_id=chalk_no_fix.finding_id,
        advisory_id=chalk_no_fix.advisory_id or "",
        package=chalk_no_fix.dependency.name,
        current_version=chalk_no_fix.dependency.version,
        title=chalk_no_fix.title,
        description=chalk_no_fix.description,
        reason="no_fix_version_in_osv",
    )
    exclusive_skip = NoFixSkip(
        finding_id=exclusive_finding.finding_id,
        advisory_id=exclusive_finding.advisory_id or "",
        package=exclusive_finding.dependency.name,
        current_version=exclusive_finding.dependency.version,
        title=exclusive_finding.title,
        description=exclusive_finding.description,
        reason="no_fix_version_in_osv",
    )
    report = _report(
        entries=(_entry((with_fix,), package="chalk", from_version="4.1.2"),),
        findings_snapshot=(with_fix, chalk_no_fix, exclusive_finding),
        skipped=(mixed_skip, exclusive_skip),
    )
    deps = _deps(("chalk", "4.1.2"), ("left-pad", "1.3.0"))
    counts = build_scan_counts(report, deps)

    assert counts.package_status_no_fix == 1
    assert counts.package_status_mixed_no_fix == 1
    assert counts.package_status_no_fix + counts.package_status_mixed_no_fix == 2
    assert counts.balance.ok is True
