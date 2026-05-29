"""Tests for fix-confidence models, classifier, kill switch, and engine."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from pathlib import Path

import pytest

import arguss.engine.fix_confidence as fix_confidence_mod
from arguss.core.models import (
    FixCandidate,
    FixConfidence,
    FixKind,
    FixTier,
    PipelineSnapshot,
    TestReality,
    TrustDelta,
    TrustFlag,
)
from arguss.engine.fix_confidence import ENGINE_VERSION, compute_fix_confidence
from arguss.engine.fix_kind import classify_fix_kind
from arguss.engine.kill_switch import is_kill_switch_active

_FIXED_TIME = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def kill_switch_off(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Ensure kill switch is inactive without touching the default /tmp path."""
    monkeypatch.delenv("ARGUSS_KILL_SWITCH", raising=False)
    monkeypatch.setenv("ARGUSS_KILL_SWITCH_FILE_PATH", str(tmp_path / "kill_switch_absent"))


@pytest.fixture
def fixed_time(monkeypatch: pytest.MonkeyPatch) -> datetime:
    monkeypatch.setattr(fix_confidence_mod, "_utc_now", lambda: _FIXED_TIME)
    return _FIXED_TIME


def _candidate(
    *,
    package: str = "lodash",
    from_version: str = "4.17.20",
    to_version: str = "4.17.21",
    fix_kind: FixKind = FixKind.PATCH,
    source_finding_ids: tuple[str, ...] = ("GHSA-test",),
    repo_id: str = "example/repo",
) -> FixCandidate:
    return FixCandidate(
        package=package,
        from_version=from_version,
        to_version=to_version,
        fix_kind=fix_kind,
        source_finding_ids=source_finding_ids,
        repo_id=repo_id,
    )


def _safe_trust_delta(
    *,
    flags: tuple[TrustFlag, ...] = (),
    safe_to_auto_merge: bool = True,
) -> TrustDelta:
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
        flags=flags,
        safe_to_auto_merge=safe_to_auto_merge,
    )


def _safe_pipeline() -> PipelineSnapshot:
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
        repo_path="/tmp/repo",
        workflow_files=(),
        zizmor_findings=(),
        test_reality=tr,
        subscore=0,
    )


def _unsafe_pipeline(
    *,
    reasons_blocked: tuple[str, ...] = ("no test files in your project",),
) -> PipelineSnapshot:
    tr = TestReality(
        has_test_script=True,
        test_script_is_no_op=False,
        has_test_files=False,
        test_count=0,
        workflow_runs_tests=True,
        safe_to_auto_merge=False,
        reasons_blocked=reasons_blocked,
    )
    return PipelineSnapshot(
        repo_path="/tmp/repo",
        workflow_files=(),
        zizmor_findings=(),
        test_reality=tr,
        subscore=40,
    )


def _evaluate(
    candidate: FixCandidate,
    trust_delta: TrustDelta | None,
    pipeline_snapshot: PipelineSnapshot | None,
    *,
    project_veto: bool = False,
) -> FixConfidence:
    return compute_fix_confidence(
        candidate,
        trust_delta,
        pipeline_snapshot,
        project_veto=project_veto,
    )


# --- Model and identity (1–3) ---


def test_fix_candidate_candidate_id_deterministic() -> None:
    c1 = _candidate()
    c2 = _candidate()
    assert c1.candidate_id == c2.candidate_id
    assert len(c1.candidate_id) == 16


def test_fix_candidate_candidate_id_differs_for_different_inputs() -> None:
    a = _candidate(source_finding_ids=("GHSA-a",))
    b = _candidate(source_finding_ids=("GHSA-b",))
    assert a.candidate_id != b.candidate_id


def test_fix_candidate_is_frozen() -> None:
    c = _candidate()
    with pytest.raises(dataclasses.FrozenInstanceError):
        c.package = "evil"  # type: ignore[misc]


# --- FixKind classifier (4–8) ---


def test_classify_fix_kind_patch() -> None:
    assert classify_fix_kind("1.2.3", "1.2.4") is FixKind.PATCH


def test_classify_fix_kind_minor() -> None:
    assert classify_fix_kind("1.2.3", "1.3.0") is FixKind.MINOR


def test_classify_fix_kind_major() -> None:
    assert classify_fix_kind("1.2.3", "2.0.0") is FixKind.MAJOR


def test_classify_fix_kind_strips_v_prefix() -> None:
    assert classify_fix_kind("v1.2.3", "v1.2.4") is FixKind.PATCH


def test_classify_fix_kind_unparseable_is_major() -> None:
    assert classify_fix_kind("garbage", "1.0.0") is FixKind.MAJOR


# --- Kill switch (9–12) ---


def test_kill_switch_env_active(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ARGUSS_KILL_SWITCH", "YES")
    monkeypatch.setenv("ARGUSS_KILL_SWITCH_FILE_PATH", str(tmp_path / "unused"))
    assert is_kill_switch_active() is True


def test_kill_switch_file_active(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("ARGUSS_KILL_SWITCH", raising=False)
    flag = tmp_path / "operator_flag"
    flag.touch()
    monkeypatch.setenv("ARGUSS_KILL_SWITCH_FILE_PATH", str(flag))
    assert is_kill_switch_active() is True


def test_kill_switch_inactive(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("ARGUSS_KILL_SWITCH", raising=False)
    monkeypatch.setenv("ARGUSS_KILL_SWITCH_FILE_PATH", str(tmp_path / "no_flag_here"))
    assert is_kill_switch_active() is False


def test_kill_switch_declines_fix_confidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fixed_time: datetime,
) -> None:
    monkeypatch.setenv("ARGUSS_KILL_SWITCH", "1")
    monkeypatch.setenv("ARGUSS_KILL_SWITCH_FILE_PATH", str(tmp_path / "unused"))
    verdict = _evaluate(_candidate(), _safe_trust_delta(), _safe_pipeline())
    assert verdict.tier is FixTier.DECLINE
    assert verdict.veto_signals == ("kill_switch",)
    assert verdict.score == 0
    assert any("kill switch" in r.lower() for r in verdict.reasons)
    assert verdict.evaluated_at == fixed_time


# --- Engine evaluation (13–23) ---


def test_clean_patch_auto_merge(
    kill_switch_off: None,
    fixed_time: datetime,
) -> None:
    verdict = _evaluate(_candidate(), _safe_trust_delta(), _safe_pipeline())
    assert verdict.tier is FixTier.AUTO_MERGE
    assert verdict.score == 100
    assert verdict.veto_signals == ()


def test_clean_minor_auto_merge(
    kill_switch_off: None,
    fixed_time: datetime,
) -> None:
    candidate = _candidate(
        from_version="1.2.3",
        to_version="1.3.0",
        fix_kind=FixKind.MINOR,
    )
    verdict = _evaluate(candidate, _safe_trust_delta(), _safe_pipeline())
    assert verdict.tier is FixTier.AUTO_MERGE
    assert verdict.score == 100


def test_major_fix_review_required(
    kill_switch_off: None,
    fixed_time: datetime,
) -> None:
    candidate = _candidate(
        from_version="1.2.3",
        to_version="2.0.0",
        fix_kind=FixKind.MAJOR,
    )
    verdict = _evaluate(candidate, _safe_trust_delta(), _safe_pipeline())
    assert verdict.tier is FixTier.REVIEW_REQUIRED
    assert "fix_kind.major" in verdict.veto_signals
    assert verdict.score == 50


def test_trust_delta_none_review_required(
    kill_switch_off: None,
    fixed_time: datetime,
) -> None:
    verdict = _evaluate(_candidate(), None, _safe_pipeline())
    assert verdict.tier is FixTier.REVIEW_REQUIRED
    assert verdict.veto_signals == ("trust.unavailable",)
    assert verdict.score == 80


def test_trust_ownership_transfer_review_required(
    kill_switch_off: None,
    fixed_time: datetime,
) -> None:
    trust = _safe_trust_delta(
        flags=(TrustFlag.OWNERSHIP_TRANSFER,),
        safe_to_auto_merge=False,
    )
    verdict = _evaluate(_candidate(), trust, _safe_pipeline())
    assert verdict.tier is FixTier.REVIEW_REQUIRED
    assert "trust.ownership_transferred" in verdict.veto_signals
    assert verdict.score == 85


def test_trust_new_maintainer_review_required(
    kill_switch_off: None,
    fixed_time: datetime,
) -> None:
    trust = _safe_trust_delta(
        flags=(TrustFlag.NEW_MAINTAINER,),
        safe_to_auto_merge=False,
    )
    verdict = _evaluate(_candidate(), trust, _safe_pipeline())
    assert verdict.tier is FixTier.REVIEW_REQUIRED
    assert "trust.new_maintainer" in verdict.veto_signals


def test_pipeline_snapshot_none_review_required(
    kill_switch_off: None,
    fixed_time: datetime,
) -> None:
    verdict = _evaluate(_candidate(), _safe_trust_delta(), None)
    assert verdict.tier is FixTier.REVIEW_REQUIRED
    assert verdict.veto_signals == ("pipeline.unavailable",)
    assert verdict.score == 75


def test_pipeline_test_reality_fail_review_required(
    kill_switch_off: None,
    fixed_time: datetime,
) -> None:
    verdict = _evaluate(_candidate(), _safe_trust_delta(), _unsafe_pipeline())
    assert verdict.tier is FixTier.REVIEW_REQUIRED
    assert verdict.veto_signals == ("pipeline.test_reality",)
    assert verdict.score == 75
    assert any("your project's ci provides no test signal" in r.lower() for r in verdict.reasons)
    assert any("cannot verify behavior post-upgrade" in r.lower() for r in verdict.reasons)


def test_project_veto_decline(
    kill_switch_off: None,
    fixed_time: datetime,
) -> None:
    verdict = _evaluate(
        _candidate(),
        _safe_trust_delta(),
        _safe_pipeline(),
        project_veto=True,
    )
    assert verdict.tier is FixTier.DECLINE
    assert verdict.veto_signals == ("project_veto",)
    assert verdict.score == 0


def test_multiple_vetoes_simultaneously(
    kill_switch_off: None,
    fixed_time: datetime,
) -> None:
    candidate = _candidate(
        from_version="1.2.3",
        to_version="2.0.0",
        fix_kind=FixKind.MAJOR,
    )
    trust = _safe_trust_delta(
        flags=(TrustFlag.OWNERSHIP_TRANSFER, TrustFlag.NEW_MAINTAINER),
        safe_to_auto_merge=False,
    )
    verdict = _evaluate(candidate, trust, _unsafe_pipeline())
    assert verdict.tier is FixTier.REVIEW_REQUIRED
    assert verdict.veto_signals == (
        "fix_kind.major",
        "pipeline.test_reality",
        "trust.new_maintainer",
        "trust.ownership_transferred",
    )
    assert verdict.score == 1


def test_auto_merge_reason_mentions_fix_kind(
    kill_switch_off: None,
    fixed_time: datetime,
) -> None:
    verdict = _evaluate(
        _candidate(fix_kind=FixKind.MINOR, from_version="1.2.0", to_version="1.3.0"),
        _safe_trust_delta(),
        _safe_pipeline(),
    )
    assert verdict.tier is FixTier.AUTO_MERGE
    assert len(verdict.reasons) == 1
    reason = verdict.reasons[0]
    assert reason
    assert "minor-level" in reason


# --- Audit trail (24–26) ---


def test_fix_confidence_evaluated_at_timezone_aware_utc(
    kill_switch_off: None,
    fixed_time: datetime,
) -> None:
    verdict = _evaluate(_candidate(), _safe_trust_delta(), _safe_pipeline())
    assert verdict.evaluated_at.tzinfo is UTC
    assert verdict.evaluated_at == fixed_time


def test_fix_confidence_engine_version_matches_constant(
    kill_switch_off: None,
) -> None:
    verdict = _evaluate(_candidate(), _safe_trust_delta(), _safe_pipeline())
    assert verdict.engine_version == ENGINE_VERSION


def test_fix_confidence_candidate_id_matches_candidate(
    kill_switch_off: None,
) -> None:
    candidate = _candidate()
    verdict = _evaluate(candidate, _safe_trust_delta(), _safe_pipeline())
    assert verdict.candidate_id == candidate.candidate_id


# --- Determinism (27) ---


def test_compute_fix_confidence_deterministic(
    kill_switch_off: None,
    fixed_time: datetime,
) -> None:
    candidate = _candidate()
    trust = _safe_trust_delta()
    pipeline = _safe_pipeline()
    first = _evaluate(candidate, trust, pipeline)
    second = _evaluate(candidate, trust, pipeline)
    assert first == second
