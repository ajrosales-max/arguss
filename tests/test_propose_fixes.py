"""Tests for fix discovery, propose orchestration, and propose-fixes CLI."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import pytest
from typer.testing import CliRunner

import arguss.cli as cli_mod
import arguss.engine.fix_confidence as fix_confidence_mod
import arguss.engine.propose as propose_mod
from arguss.cli import app
from arguss.core.models import (
    Dependency,
    Finding,
    FixKind,
    FixTier,
    LensScore,
    PipelineSnapshot,
    ScanSkip,
    TestReality,
    TrustDelta,
)
from arguss.engine.fix_confidence import ENGINE_VERSION
from arguss.engine.fix_discovery import discover_fix_candidates
from arguss.engine.propose import (
    ProposalEntry,
    ProposalReport,
    ProposalSummary,
    propose_fixes,
)
from arguss.lenses._trust_client import TrustClientError
from arguss.settings import Settings
from arguss.settings import settings as live_settings

FIXTURES = Path(__file__).parent / "fixtures" / "lockfiles"
REPOS = Path(__file__).parent / "fixtures" / "repos"
RUNNER = CliRunner()

_FIXED_TIME = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def kill_switch_off(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("ARGUSS_KILL_SWITCH", raising=False)
    monkeypatch.setenv("ARGUSS_KILL_SWITCH_FILE_PATH", str(tmp_path / "kill_switch_absent"))


@pytest.fixture
def propose_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db = tmp_path / "propose.db"
    monkeypatch.setattr(live_settings, "db_path", db)
    monkeypatch.setattr(Settings, "db_path", db)
    return db


@pytest.fixture
def fixed_time(monkeypatch: pytest.MonkeyPatch) -> datetime:
    monkeypatch.setattr(fix_confidence_mod, "_utc_now", lambda: _FIXED_TIME)
    return _FIXED_TIME


def _cve_finding(
    *,
    name: str = "lodash",
    version: str = "4.17.20",
    advisory_id: str = "GHSA-test",
    fixed_versions: tuple[str, ...] = ("4.17.21",),
) -> Finding:
    return Finding(
        dependency=Dependency(name=name, version=version, direct=True),
        lens="cve",
        severity="high",
        score=75.0,
        title=f"{advisory_id}: test vulnerability",
        description="test description",
        advisory_id=advisory_id,
        fixed_versions=fixed_versions,
    )


def _safe_pipeline(repo_path: str = "/tmp/repo") -> PipelineSnapshot:
    tr = TestReality(
        has_test_script=True,
        test_script_is_no_op=False,
        has_test_files=True,
        test_count=5,
        workflow_runs_tests=True,
        safe_to_auto_merge=True,
        reasons_blocked=(),
    )
    return PipelineSnapshot(
        repo_path=repo_path,
        workflow_files=(),
        zizmor_findings=(),
        test_reality=tr,
        subscore=0,
    )


def _safe_trust_delta() -> TrustDelta:
    return TrustDelta(
        package="lodash",
        from_version="4.17.20",
        to_version="4.17.21",
        maintainers_added=(),
        maintainers_removed=(),
        ownership_transferred=False,
        days_between_publishes=10,
        publish_cadence_anomaly=False,
        weekly_downloads_change_pct=0.0,
        flags=(),
        safe_to_auto_merge=True,
    )


def _mock_vulnerability_lens(
    monkeypatch: pytest.MonkeyPatch,
    findings: list[Finding],
) -> None:
    lens_score = LensScore(lens="cve", score=80.0 if findings else 0.0, findings=findings)
    instance = mock.MagicMock()
    instance.scan.return_value = lens_score
    monkeypatch.setattr(propose_mod, "VulnerabilityLens", lambda cache: instance)


# --- Fix discovery (1–6) ---


def test_discover_fix_with_fixed_in() -> None:
    finding = _cve_finding(fixed_versions=("4.17.21",))
    candidates = discover_fix_candidates(finding, "/repo/a")
    assert len(candidates) == 1
    c = candidates[0]
    assert c.package == "lodash"
    assert c.from_version == "4.17.20"
    assert c.to_version == "4.17.21"
    assert c.source_finding_id == "GHSA-test"
    assert c.repo_id == "/repo/a"


def test_discover_fix_no_fixed_in() -> None:
    finding = _cve_finding(fixed_versions=())
    assert discover_fix_candidates(finding, "/repo/a") == []


def test_discover_fix_kind_classified_correctly() -> None:
    patch_f = _cve_finding(version="1.2.3", fixed_versions=("1.2.4",))
    assert discover_fix_candidates(patch_f, "/r")[0].fix_kind is FixKind.PATCH

    minor_f = _cve_finding(version="1.2.3", fixed_versions=("1.3.0",))
    assert discover_fix_candidates(minor_f, "/r")[0].fix_kind is FixKind.MINOR

    major_f = _cve_finding(version="1.2.3", fixed_versions=("2.0.0",))
    assert discover_fix_candidates(major_f, "/r")[0].fix_kind is FixKind.MAJOR


def test_discover_fix_picks_lowest_fixed_in_when_multiple() -> None:
    finding = _cve_finding(version="1.2.3", fixed_versions=("1.3.0", "1.2.4", "1.10.0"))
    assert discover_fix_candidates(finding, "/repo")[0].to_version == "1.2.4"


def test_discover_fix_skips_invalid_fixed_in(caplog: pytest.LogCaptureFixture) -> None:
    finding = _cve_finding(version="1.2.3", fixed_versions=("1.0.0",))
    with caplog.at_level(logging.WARNING):
        assert discover_fix_candidates(finding, "/repo") == []
    assert "GHSA-test" in caplog.text


def test_candidate_id_includes_repo_id() -> None:
    finding = _cve_finding()
    a = discover_fix_candidates(finding, "/repo/a")[0]
    b = discover_fix_candidates(finding, "/repo/b")[0]
    assert a.candidate_id != b.candidate_id


# --- Orchestration (7–14) ---


def test_propose_fixes_empty_lockfile(
    tmp_path: Path,
    propose_db: Path,
    kill_switch_off: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        '{"lockfileVersion": 3, "packages": {"": {"name": "x", "version": "1.0.0"}}}'
    )
    monkeypatch.setattr(propose_mod, "fetch_pipeline_snapshot", lambda _p: _safe_pipeline())

    report = propose_fixes(lockfile)

    assert report.summary.total_findings == 0
    assert report.summary.total_candidates == 0
    assert report.entries == ()
    assert report.skipped_findings == ()


def test_propose_fixes_no_vulnerabilities(
    tmp_path: Path,
    propose_db: Path,
    kill_switch_off: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lockfile = FIXTURES / "minimal.json"
    _mock_vulnerability_lens(monkeypatch, [])
    monkeypatch.setattr(propose_mod, "fetch_pipeline_snapshot", lambda _p: _safe_pipeline())

    report = propose_fixes(lockfile)

    assert report.summary.total_findings == 0
    assert report.entries == ()


def test_propose_fixes_one_vulnerability(
    propose_db: Path,
    kill_switch_off: None,
    fixed_time: datetime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _cve_finding()
    _mock_vulnerability_lens(monkeypatch, [finding])
    monkeypatch.setattr(propose_mod, "fetch_pipeline_snapshot", lambda _p: _safe_pipeline())
    monkeypatch.setattr(propose_mod, "fetch_delta", lambda *a, **k: _safe_trust_delta())

    report = propose_fixes(FIXTURES / "minimal.json")

    assert len(report.entries) == 1
    entry = report.entries[0]
    assert entry.finding.advisory_id == "GHSA-test"
    assert entry.candidate.to_version == "4.17.21"
    assert entry.verdict.candidate_id == entry.candidate.candidate_id
    assert entry.verdict.evaluated_at == fixed_time


def test_propose_fixes_summary_counts(
    propose_db: Path,
    kill_switch_off: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    findings = [
        _cve_finding(advisory_id="GHSA-a"),
        _cve_finding(advisory_id="GHSA-b", version="1.0.0", fixed_versions=("2.0.0",)),
    ]
    _mock_vulnerability_lens(monkeypatch, findings)
    monkeypatch.setattr(propose_mod, "fetch_pipeline_snapshot", lambda _p: _safe_pipeline())

    def _trust_for_package(cache: object, package: str, fv: str, tv: str) -> TrustDelta:
        delta = _safe_trust_delta()
        if package == "lodash" and tv == "4.17.21":
            return delta
        return TrustDelta(
            package=package,
            from_version=fv,
            to_version=tv,
            maintainers_added=(),
            maintainers_removed=(),
            ownership_transferred=False,
            days_between_publishes=10,
            publish_cadence_anomaly=False,
            weekly_downloads_change_pct=0.0,
            flags=(),
            safe_to_auto_merge=True,
        )

    monkeypatch.setattr(propose_mod, "fetch_delta", _trust_for_package)

    report = propose_fixes(FIXTURES / "minimal.json")

    assert report.summary.total_findings == 2
    assert report.summary.total_candidates == 2
    assert (
        report.summary.auto_merge_count
        + report.summary.review_required_count
        + report.summary.decline_count
        == len(report.entries)
    )
    assert report.summary.auto_merge_count == 1
    assert report.summary.review_required_count == 1


def test_propose_fixes_skipped_findings(
    propose_db: Path,
    kill_switch_off: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    findings = [
        _cve_finding(advisory_id="GHSA-has-fix"),
        _cve_finding(advisory_id="GHSA-no-fix", fixed_versions=()),
    ]
    _mock_vulnerability_lens(monkeypatch, findings)
    monkeypatch.setattr(propose_mod, "fetch_pipeline_snapshot", lambda _p: _safe_pipeline())
    monkeypatch.setattr(propose_mod, "fetch_delta", lambda *a, **k: _safe_trust_delta())

    report = propose_fixes(FIXTURES / "minimal.json")

    assert report.skipped_findings == ("GHSA-no-fix",)
    assert len(report.entries) == 1


def test_propose_fixes_osv_unavailable_skipped(
    propose_db: Path,
    kill_switch_off: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    osv_skip = ScanSkip(
        reason="osv_unavailable",
        detail="OSV API returned an error; vulnerability scan was incomplete",
        lens="vulnerability",
    )
    lens_score = LensScore(lens="cve", score=0.0, findings=[], scan_skips=[osv_skip])
    instance = mock.MagicMock()
    instance.scan.return_value = lens_score
    monkeypatch.setattr(propose_mod, "VulnerabilityLens", lambda cache: instance)
    monkeypatch.setattr(propose_mod, "fetch_pipeline_snapshot", lambda _p: _safe_pipeline())

    report = propose_fixes(FIXTURES / "minimal.json")

    assert report.summary.total_findings == 0
    assert report.entries == ()
    assert report.skipped_findings == (osv_skip,)


def test_propose_fixes_trust_fetch_failure_degrades(
    propose_db: Path,
    kill_switch_off: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_vulnerability_lens(monkeypatch, [_cve_finding()])
    monkeypatch.setattr(propose_mod, "fetch_pipeline_snapshot", lambda _p: _safe_pipeline())

    def _fail_delta(*_args: object, **_kwargs: object) -> TrustDelta:
        raise TrustClientError("npm registry: unavailable")

    monkeypatch.setattr(propose_mod, "fetch_delta", _fail_delta)

    report = propose_fixes(FIXTURES / "minimal.json")

    assert len(report.entries) == 1
    assert report.entries[0].verdict.tier is FixTier.REVIEW_REQUIRED
    assert "trust.unavailable" in report.entries[0].verdict.veto_signals


def test_propose_fixes_uses_lockfile_parent_when_no_repo_path(
    tmp_path: Path,
    propose_db: Path,
    kill_switch_off: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sub = tmp_path / "nested"
    sub.mkdir()
    lockfile = sub / "package-lock.json"
    lockfile.write_text(
        '{"lockfileVersion": 3, "packages": {"": {"name": "x", "version": "1.0.0"}, '
        '"node_modules/lodash": {"version": "4.17.20"}}}'
    )
    _mock_vulnerability_lens(monkeypatch, [])
    captured: list[Path] = []

    def _capture_pipeline(repo: Path) -> PipelineSnapshot:
        captured.append(repo)
        return _safe_pipeline(str(repo))

    monkeypatch.setattr(propose_mod, "fetch_pipeline_snapshot", _capture_pipeline)

    report = propose_fixes(lockfile, repo_path=None)

    assert report.repo_path == str(sub.resolve())
    assert captured == [sub.resolve()]


def test_propose_fixes_pipeline_snapshot_fetched_once(
    propose_db: Path,
    kill_switch_off: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    findings = [
        _cve_finding(advisory_id="GHSA-1"),
        _cve_finding(advisory_id="GHSA-2", version="1.0.0", fixed_versions=("1.0.1",)),
    ]
    _mock_vulnerability_lens(monkeypatch, findings)
    pipeline_calls: list[Path] = []

    def _count_pipeline(repo: Path) -> PipelineSnapshot:
        pipeline_calls.append(repo)
        return _safe_pipeline(str(repo))

    monkeypatch.setattr(propose_mod, "fetch_pipeline_snapshot", _count_pipeline)
    monkeypatch.setattr(propose_mod, "fetch_delta", lambda *a, **k: _safe_trust_delta())

    report = propose_fixes(FIXTURES / "minimal.json")

    assert len(report.entries) == 2
    assert len(pipeline_calls) == 1


# --- CLI (15–17) ---


def _fake_proposal_report() -> ProposalReport:
    finding = _cve_finding()
    candidate = discover_fix_candidates(finding, "/fake/repo")[0]
    from arguss.engine.fix_confidence import compute_fix_confidence

    verdict = compute_fix_confidence(candidate, _safe_trust_delta(), _safe_pipeline())
    return ProposalReport(
        repo_path="/fake/repo",
        lockfile_path="/fake/package-lock.json",
        entries=(ProposalEntry(finding=finding, candidate=candidate, verdict=verdict),),
        skipped_findings=(),
        summary=ProposalSummary(
            total_findings=1,
            total_candidates=1,
            auto_merge_count=1,
            review_required_count=0,
            decline_count=0,
        ),
    )


def test_cli_propose_fixes_success_against_synthetic_fixture(
    tmp_path: Path,
    kill_switch_off: None,
) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        '{"lockfileVersion": 3, "packages": {"": {"name": "synthetic", "version": "1.0.0"}}}'
    )
    fake = _fake_proposal_report()

    with mock.patch.object(cli_mod, "propose_fixes", return_value=fake):
        result = RUNNER.invoke(app, ["propose-fixes", str(lockfile)])

    assert result.exit_code == 0, result.output
    body = json.loads(result.stdout)
    assert body["summary"]["total_candidates"] == 1


def test_cli_propose_fixes_lockfile_not_found_exits_1() -> None:
    missing = "/no/such/package-lock.json"
    result = RUNNER.invoke(app, ["propose-fixes", missing])
    assert result.exit_code != 0


def test_cli_propose_fixes_json_output_validates_schema(
    tmp_path: Path,
    kill_switch_off: None,
) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        '{"lockfileVersion": 3, "packages": {"": {"name": "synthetic", "version": "1.0.0"}}}'
    )

    with mock.patch.object(cli_mod, "propose_fixes", return_value=_fake_proposal_report()):
        result = RUNNER.invoke(app, ["propose-fixes", str(lockfile)])

    body = json.loads(result.stdout)
    assert set(body.keys()) == {
        "repo_path",
        "lockfile_path",
        "entries",
        "skipped_findings",
        "summary",
    }
    summary = body["summary"]
    assert set(summary.keys()) == {
        "total_findings",
        "total_candidates",
        "auto_merge_count",
        "review_required_count",
        "decline_count",
    }
    assert len(body["entries"]) == 1
    entry = body["entries"][0]
    assert set(entry.keys()) == {"finding", "candidate", "verdict"}
    assert entry["finding"]["advisory_id"] == "GHSA-test"
    assert entry["candidate"]["to_version"] == "4.17.21"
    verdict = entry["verdict"]
    assert verdict["tier"] == FixTier.AUTO_MERGE.value
    assert verdict["engine_version"] == ENGINE_VERSION
    assert isinstance(verdict["reasons"], list)
    assert isinstance(verdict["veto_signals"], list)


# --- Integration ---


@pytest.mark.integration
def test_propose_fixes_integration_real_world_express(
    tmp_path: Path,
    kill_switch_off: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: real lockfile, real OSV calls, real engine evaluation."""
    db = tmp_path / "integration.db"
    monkeypatch.setattr(live_settings, "db_path", db)
    monkeypatch.setattr(Settings, "db_path", db)

    report = propose_fixes(FIXTURES / "real-world.json")

    assert report.summary.total_findings >= 1
    assert report.summary.total_candidates == len(report.entries)
    assert len(report.entries) >= 1
    assert (
        report.summary.auto_merge_count
        + report.summary.review_required_count
        + report.summary.decline_count
        == len(report.entries)
    )

    for entry in report.entries:
        assert entry.finding.advisory_id
        assert entry.candidate.candidate_id
        assert entry.verdict.candidate_id == entry.candidate.candidate_id
        assert entry.verdict.engine_version == ENGINE_VERSION
        assert entry.verdict.tier in (
            FixTier.AUTO_MERGE,
            FixTier.REVIEW_REQUIRED,
            FixTier.DECLINE,
        )
