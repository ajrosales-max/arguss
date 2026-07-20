"""Tests for Mode C action-path observability."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import pytest
from fastapi import HTTPException, status

import arguss.web.github_action as github_action_mod
import arguss.web.mode_c_workflow as mode_c_mod
from arguss.core.models import (
    Dependency,
    Finding,
    FixCandidate,
    FixConfidence,
    FixKind,
    FixTier,
)
from arguss.engine.fix_confidence import ENGINE_VERSION
from arguss.engine.propose import ProposalEntry, ProposalReport, ProposalSummary
from arguss.web.git_clone import GitCloneError
from arguss.web.github_action import (
    ActionResult,
    GitHubActionError,
    http_detail_for_github_action_error,
    run_mode_c_actions,
)
from arguss.web.mode_c_workflow import (
    _clone_error_detail,
    _clone_error_status,
    execute_scan_with_action,
)

_TEST_INSTALLATION_ID = 12345
_SECRET_TOKEN = "ghs_must_never_appear_in_mode_c_action_logs"
_FIXTURES = Path(__file__).parent / "fixtures" / "lockfiles"
_FIXED_TIME = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)
_RATE_LIMIT_RESET = 1_704_067_200


def _candidate(*, package: str = "left-pad") -> FixCandidate:
    return FixCandidate(
        package=package,
        from_version="1.3.0",
        to_version="1.3.1",
        fix_kind=FixKind.PATCH,
        source_finding_ids=("GHSA-test",),
        repo_id="/tmp/repo",
    )


def _finding(*, package: str = "left-pad") -> Finding:
    return Finding(
        dependency=Dependency(name=package, version="1.3.0", direct=True),
        lens="cve",
        severity="high",
        score=75.0,
        title="GHSA-test: test vulnerability",
        description="test description",
        advisory_id="GHSA-test",
        source_url="https://github.com/advisories/GHSA-test",
    )


def _verdict(candidate: FixCandidate) -> FixConfidence:
    return FixConfidence(
        candidate_id=candidate.candidate_id,
        tier=FixTier.AUTO_MERGE,
        score=95,
        reasons=("trust and pipeline signals are clean",),
        veto_signals=(),
        evaluated_at=_FIXED_TIME,
        engine_version=ENGINE_VERSION,
    )


def _proposal_entry(*, package: str = "left-pad") -> ProposalEntry:
    candidate = _candidate(package=package)
    finding = _finding(package=package)
    return ProposalEntry(
        finding=finding,
        related_findings=(finding,),
        candidate=candidate,
        verdict=_verdict(candidate),
    )


def _proposal_report(repo: Path) -> ProposalReport:
    entry = _proposal_entry()
    return ProposalReport(
        repo_path=str(repo),
        lockfile_path=str(repo / "package-lock.json"),
        entries=(entry,),
        skipped_findings=(),
        summary=ProposalSummary(
            total_findings=1,
            total_candidates=1,
            auto_merge_count=1,
            review_required_count=0,
            decline_count=0,
        ),
    )


def _prepare_clone_dest(_clone_url: str, dest: Path, ref: str | None = None) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "package-lock.json").write_bytes((_FIXTURES / "minimal.json").read_bytes())
    (dest / "package.json").write_text('{"name":"t","version":"1.0.0"}\n', encoding="utf-8")
    return dest


@pytest.mark.parametrize(
    ("kind", "expected_status", "expected_detail"),
    [
        (
            GitCloneError.KIND_GIT_EXECUTABLE,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "git executable not available on server",
        ),
        (
            GitCloneError.KIND_TIMEOUT,
            status.HTTP_504_GATEWAY_TIMEOUT,
            "Clone took too long; repository may be too large",
        ),
        (
            GitCloneError.KIND_CLONE_FAILED,
            status.HTTP_404_NOT_FOUND,
            "Repository not found or not accessible",
        ),
        (
            GitCloneError.KIND_REF_NOT_FOUND,
            status.HTTP_404_NOT_FOUND,
            "Ref 'v1.0.0' not found in repository",
        ),
    ],
)
def test_clone_error_mapping_by_kind(
    kind: str,
    expected_status: int,
    expected_detail: str,
) -> None:
    ref = "v1.0.0" if kind == GitCloneError.KIND_REF_NOT_FOUND else None
    exc = GitCloneError("underlying clone failure", kind=kind, ref=ref)
    assert _clone_error_status(exc) == expected_status
    assert _clone_error_detail(exc) == expected_detail


def test_github_action_error_401_maps_to_invalid_pat() -> None:
    exc = GitHubActionError("bad creds", status_code=status.HTTP_401_UNAUTHORIZED)
    code, detail = http_detail_for_github_action_error(exc)
    assert code == status.HTTP_401_UNAUTHORIZED
    assert detail == "Invalid or expired PAT"


def test_github_action_error_rate_limit_403_before_pat_scope() -> None:
    exc = GitHubActionError(
        "rate limit",
        status_code=status.HTTP_403_FORBIDDEN,
        rate_limit_exhausted=True,
        rate_limit_reset_epoch=_RATE_LIMIT_RESET,
    )
    code, detail = http_detail_for_github_action_error(exc)
    assert code == status.HTTP_403_FORBIDDEN
    assert detail.startswith("GitHub rate limit hit, retry after ")
    assert "2024-01-01 00:00:00 UTC" in detail


def test_github_action_error_plain_403_maps_to_pat_scope() -> None:
    exc = GitHubActionError("forbidden", status_code=status.HTTP_403_FORBIDDEN)
    code, detail = http_detail_for_github_action_error(exc)
    assert code == status.HTTP_403_FORBIDDEN
    assert detail == "PAT lacks repo scope on this repository"


def test_github_action_error_404_maps_to_not_found() -> None:
    exc = GitHubActionError("missing", status_code=status.HTTP_404_NOT_FOUND)
    code, detail = http_detail_for_github_action_error(exc)
    assert code == status.HTTP_404_NOT_FOUND
    assert detail == "Repository not found or not accessible"


def test_github_action_error_generic_includes_class_name() -> None:
    exc = GitHubActionError("network down")
    code, detail = http_detail_for_github_action_error(exc)
    assert code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert detail == "Action failed: GitHubActionError"


@pytest.mark.asyncio
async def test_workflow_entry_log_includes_repo_ref_action_id(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    repo = tmp_path / "express"
    report = _proposal_report(repo)

    with (
        caplog.at_level(logging.INFO, logger="arguss.web.mode_c_workflow"),
        mock.patch.object(mode_c_mod, "shallow_clone", side_effect=_prepare_clone_dest),
        mock.patch.object(mode_c_mod, "propose_fixes", return_value=report),
        mock.patch.object(mode_c_mod, "run_mode_c_actions", return_value=[]),
        mock.patch.object(mode_c_mod, "save_scan_inputs"),
        mock.patch.object(mode_c_mod, "scan_input_hash", return_value="scan-hash"),
    ):
        await execute_scan_with_action(
            url="https://github.com/o/r",
            installation_id=_TEST_INSTALLATION_ID,
            ref="main",
            action_id="action-123",
        )

    entry_logs = [r for r in caplog.records if r.getMessage() == "mode C action workflow started"]
    assert len(entry_logs) == 1
    record = entry_logs[0]
    assert record.repo == "o/r"
    assert record.ref == "main"
    assert record.action_id == "action-123"


@pytest.mark.asyncio
async def test_clone_failure_logged_with_exception_class_before_mapping(
    caplog: pytest.LogCaptureFixture,
) -> None:
    clone_error = GitCloneError(
        "git executable not found on PATH",
        kind=GitCloneError.KIND_GIT_EXECUTABLE,
    )

    with (
        caplog.at_level(logging.ERROR, logger="arguss.web.mode_c_workflow"),
        mock.patch.object(mode_c_mod, "shallow_clone", side_effect=clone_error),
        pytest.raises(HTTPException) as exc_info,
    ):
        await execute_scan_with_action(
            url="https://github.com/o/r",
            installation_id=_TEST_INSTALLATION_ID,
            ref="HEAD",
        )

    assert exc_info.value.detail == "git executable not available on server"
    failure_logs = [r for r in caplog.records if "mode C clone failed" in r.getMessage()]
    assert len(failure_logs) == 1
    assert "GitCloneError" in failure_logs[0].getMessage()


@pytest.mark.asyncio
async def test_per_pr_outcome_logs_opened_already_exists_failed(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    work_tree = _prepare_clone_dest("https://github.com/o/r.git", tmp_path / "repo")
    entries = (
        _proposal_entry(package="left-pad"),
        _proposal_entry(package="chalk"),
        _proposal_entry(package="lodash"),
    )
    opened = ActionResult(
        candidate_id=entries[0].candidate.candidate_id,
        status="opened",
        pr_url="https://github.com/o/r/pull/1",
        pr_number=1,
        reason=None,
    )
    exists = ActionResult(
        candidate_id=entries[1].candidate.candidate_id,
        status="already_exists",
        pr_url="https://github.com/o/r/pull/2",
        pr_number=2,
        reason=None,
    )
    failed = ActionResult(
        candidate_id=entries[2].candidate.candidate_id,
        status="failed",
        pr_url=None,
        pr_number=None,
        reason="branch conflict",
    )

    with (
        caplog.at_level(logging.INFO, logger="arguss.web.github_action"),
        mock.patch.object(
            github_action_mod,
            "open_fix_pr",
            side_effect=[opened, exists, failed],
        ),
    ):
        await run_mode_c_actions(entries, work_tree, "o", "r", _TEST_INSTALLATION_ID)

    messages = [r.getMessage() for r in caplog.records]
    assert any("PR opened for left-pad (1.3.0 → 1.3.1)" in msg for msg in messages)
    assert any("PR already open for chalk (1.3.0 → 1.3.1)" in msg for msg in messages)
    assert any(
        "PR open failed for lodash (1.3.0 → 1.3.1): branch conflict" in msg for msg in messages
    )


@pytest.mark.asyncio
async def test_mode_c_action_logs_never_contain_pat(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    repo = tmp_path / "express"
    report = _proposal_report(repo)
    opened = ActionResult(
        candidate_id=report.entries[0].candidate.candidate_id,
        status="opened",
        pr_url="https://github.com/o/r/pull/9",
        pr_number=9,
        reason=None,
    )

    with (
        caplog.at_level(logging.DEBUG),
        mock.patch.object(mode_c_mod, "shallow_clone", side_effect=_prepare_clone_dest),
        mock.patch.object(mode_c_mod, "propose_fixes", return_value=report),
        mock.patch.object(mode_c_mod, "run_mode_c_actions", return_value=[opened]),
        mock.patch.object(mode_c_mod, "save_scan_inputs"),
        mock.patch.object(mode_c_mod, "scan_input_hash", return_value="scan-hash"),
    ):
        await execute_scan_with_action(
            url="https://github.com/o/r",
            installation_id=_TEST_INSTALLATION_ID,
            ref="main",
            action_id="action-secret",
        )

    for record in caplog.records:
        assert _SECRET_TOKEN not in record.getMessage()
        for value in record.__dict__.values():
            if isinstance(value, str):
                assert _SECRET_TOKEN not in value


def test_github_action_module_has_no_service_token_reference() -> None:
    source = Path("arguss/web/github_action.py").read_text(encoding="utf-8")
    assert "ARGUSS_GITHUB_TOKEN" not in source
    assert "settings.github_token" not in source


def test_auth_headers_empty_when_settings_token_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from arguss.web.github_fetch import _auth_headers

    monkeypatch.setattr("arguss.web.github_fetch.settings.github_token", None)
    assert _auth_headers() == {}


def test_auth_headers_include_bearer_when_settings_token_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from arguss.web.github_fetch import _auth_headers

    monkeypatch.setattr(
        "arguss.web.github_fetch.settings.github_token",
        "ghp_settings_test_token",
    )
    assert _auth_headers() == {"Authorization": "Bearer ghp_settings_test_token"}


_ACTION_REF = "v1.0.0"


@pytest.mark.asyncio
async def test_execute_scan_passes_ref_to_shallow_clone(tmp_path: Path) -> None:
    repo = tmp_path / "express"
    report = _proposal_report(repo)
    with (
        mock.patch.object(mode_c_mod, "shallow_clone") as clone_mock,
        mock.patch.object(mode_c_mod, "propose_fixes", return_value=report),
        mock.patch.object(mode_c_mod, "run_mode_c_actions", return_value=[]),
        mock.patch.object(mode_c_mod, "save_scan_inputs"),
        mock.patch.object(mode_c_mod, "scan_input_hash", return_value="hash"),
    ):
        clone_mock.side_effect = _prepare_clone_dest
        await execute_scan_with_action(
            url="https://github.com/o/r", installation_id=_TEST_INSTALLATION_ID, ref=_ACTION_REF
        )
    assert clone_mock.call_args.args[2] == _ACTION_REF
