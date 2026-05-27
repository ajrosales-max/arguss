"""Tests for lockfile fix, GitHub action, and POST /scan/with-action (Mode C)."""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

import httpx
import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.github_action as github_action_mod
import arguss.web.routes as routes_mod
from arguss.api import app as api_app
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
from arguss.settings import Settings
from arguss.settings import settings as live_settings
from arguss.web.github_action import (
    ActionResult,
    GitHubActionError,
    open_fix_pr,
)
from arguss.web.github_url import parse_github_url
from arguss.web.lockfile_fix import LockfileModificationError, apply_fix_to_lockfile

_SCAN_WITH_ACTION = "/scan/with-action"
_EXPRESS_URL = "https://github.com/expressjs/express"
_TEST_PAT = "ghp_test_pat_for_unit_tests_only_not_real"
_INTERNAL_DETAIL = "Internal error during analysis"
_FIXTURES = Path(__file__).parent / "fixtures" / "lockfiles"
_FIXED_TIME = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def kill_switch_off(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("ARGUSS_KILL_SWITCH", raising=False)
    monkeypatch.setenv("ARGUSS_KILL_SWITCH_FILE_PATH", str(tmp_path / "kill_switch_absent"))


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


@pytest.fixture
def work_tree(tmp_path: Path) -> Path:
    lockfile = _FIXTURES / "minimal.json"
    (tmp_path / "package-lock.json").write_bytes(lockfile.read_bytes())
    return tmp_path


def _candidate(
    *,
    package: str = "left-pad",
    from_version: str = "1.3.0",
    to_version: str = "1.3.1",
    fix_kind: FixKind = FixKind.PATCH,
    source_finding_id: str = "GHSA-test",
    repo_id: str = "/tmp/repo",
) -> FixCandidate:
    return FixCandidate(
        package=package,
        from_version=from_version,
        to_version=to_version,
        fix_kind=fix_kind,
        source_finding_id=source_finding_id,
        repo_id=repo_id,
    )


def _finding(
    *,
    package: str = "left-pad",
    version: str = "1.3.0",
    advisory_id: str = "GHSA-test",
) -> Finding:
    return Finding(
        dependency=Dependency(name=package, version=version, direct=True),
        lens="cve",
        severity="high",
        score=75.0,
        title=f"{advisory_id}: test vulnerability",
        description="test description",
        advisory_id=advisory_id,
        source_url=f"https://github.com/advisories/{advisory_id}",
    )


def _verdict(
    candidate: FixCandidate,
    *,
    tier: FixTier = FixTier.AUTO_MERGE,
) -> FixConfidence:
    return FixConfidence(
        candidate_id=candidate.candidate_id,
        tier=tier,
        score=95,
        reasons=("trust and pipeline signals are clean",),
        veto_signals=(),
        evaluated_at=_FIXED_TIME,
        engine_version=ENGINE_VERSION,
    )


def _httpx_response(
    status_code: int,
    json_body: Any | None = None,
) -> httpx.Response:
    request = httpx.Request("GET", "https://api.github.com/repos/o/r")
    if json_body is None:
        return httpx.Response(status_code, request=request)
    return httpx.Response(status_code, request=request, json=json_body)


def _mock_github_client(
    handler: Any,
) -> mock.MagicMock:
    client = mock.MagicMock(spec=httpx.Client)
    client.request.side_effect = handler
    client.close = mock.Mock()
    return client


def _happy_path_handler(
    owner: str,
    name: str,
    branch_name: str,
    *,
    default_branch: str = "main",
    base_sha: str = "abc123sha",
) -> Any:
    def handler(
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        if method == "GET" and f"/branches/{branch_name}" in url:
            return _httpx_response(404)
        if method == "GET" and url.endswith(f"/repos/{owner}/{name}"):
            return _httpx_response(200, {"default_branch": default_branch})
        if method == "GET" and f"/git/ref/heads/{default_branch}" in url:
            return _httpx_response(200, {"object": {"sha": base_sha}})
        if method == "POST" and url.endswith("/git/refs"):
            return _httpx_response(201, {})
        if method == "PUT" and "contents/package-lock.json" in url:
            return _httpx_response(200, {"content": {"sha": "newsha"}})
        if method == "POST" and url.endswith("/pulls"):
            return _httpx_response(
                201,
                {
                    "html_url": f"https://github.com/{owner}/{name}/pull/42",
                    "number": 42,
                },
            )
        return _httpx_response(500, {"message": f"unexpected {method} {url}"})

    return handler


def _proposal_entry(*, tier: FixTier, package: str = "left-pad") -> ProposalEntry:
    candidate = _candidate(package=package)
    finding = _finding(package=package)
    verdict = _verdict(candidate, tier=tier)
    return ProposalEntry(finding=finding, candidate=candidate, verdict=verdict)


def _proposal_report(
    repo: Path,
    entries: tuple[ProposalEntry, ...] = (),
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
    )


def _mock_clone_with_lockfile(dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "package-lock.json").write_bytes((_FIXTURES / "minimal.json").read_bytes())
    return dest


# --- Lockfile modifier (9) ---


def test_apply_fix_simple_direct_dep() -> None:
    lockfile_bytes = (_FIXTURES / "minimal.json").read_bytes()
    candidate = _candidate()
    result = apply_fix_to_lockfile(lockfile_bytes, candidate)
    assert result is not None
    data = json.loads(result)
    entry = data["packages"]["node_modules/left-pad"]
    assert entry["version"] == "1.3.1"
    assert data["packages"][""]["dependencies"]["left-pad"] == "1.3.1"


def test_apply_fix_top_level_transitive() -> None:
    lockfile_bytes = (_FIXTURES / "with-transitive.json").read_bytes()
    candidate = _candidate(
        package="chalk",
        from_version="4.1.2",
        to_version="4.1.3",
        source_finding_id="GHSA-chalk",
    )
    result = apply_fix_to_lockfile(lockfile_bytes, candidate)
    assert result is not None
    data = json.loads(result)
    assert data["packages"]["node_modules/chalk"]["version"] == "4.1.3"


def test_apply_fix_clears_integrity_field() -> None:
    lockfile_bytes = (_FIXTURES / "minimal.json").read_bytes()
    candidate = _candidate()
    result = apply_fix_to_lockfile(lockfile_bytes, candidate)
    assert result is not None
    entry = json.loads(result)["packages"]["node_modules/left-pad"]
    assert "integrity" not in entry


def test_apply_fix_updates_resolved_url() -> None:
    lockfile_bytes = (_FIXTURES / "minimal.json").read_bytes()
    candidate = _candidate()
    result = apply_fix_to_lockfile(lockfile_bytes, candidate)
    assert result is not None
    resolved = json.loads(result)["packages"]["node_modules/left-pad"]["resolved"]
    assert "left-pad-1.3.1.tgz" in resolved
    assert "1.3.0" not in resolved


def test_apply_fix_version_mismatch_returns_none() -> None:
    lockfile_bytes = (_FIXTURES / "minimal.json").read_bytes()
    candidate = _candidate(from_version="9.9.9")
    assert apply_fix_to_lockfile(lockfile_bytes, candidate) is None


def test_apply_fix_complex_transitive_returns_none() -> None:
    lockfile = {
        "lockfileVersion": 3,
        "packages": {
            "node_modules/foo": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
            },
            "node_modules/foo/node_modules/bar": {
                "version": "2.0.0",
                "resolved": "https://registry.npmjs.org/bar/-/bar-2.0.0.tgz",
            },
        },
    }
    candidate = _candidate(package="foo", from_version="1.0.0", to_version="1.0.1")
    assert apply_fix_to_lockfile(json.dumps(lockfile).encode(), candidate) is None


def test_apply_fix_scoped_package_simple_case() -> None:
    lockfile = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"@scope/pkg": "1.0.0"}},
            "node_modules/@scope/pkg": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz",
                "integrity": "sha512-deadbeef",
            },
        },
    }
    candidate = _candidate(
        package="@scope/pkg",
        from_version="1.0.0",
        to_version="1.0.1",
    )
    result = apply_fix_to_lockfile(json.dumps(lockfile).encode(), candidate)
    assert result is not None
    entry = json.loads(result)["packages"]["node_modules/@scope/pkg"]
    assert entry["version"] == "1.0.1"
    assert "1.0.1" in entry["resolved"]


def test_apply_fix_malformed_lockfile_raises() -> None:
    candidate = _candidate()
    with pytest.raises(LockfileModificationError, match="not valid JSON"):
        apply_fix_to_lockfile(b"{not json", candidate)


def test_apply_fix_preserves_other_packages() -> None:
    lockfile_bytes = (_FIXTURES / "with-transitive.json").read_bytes()
    candidate = _candidate(
        package="chalk",
        from_version="4.1.2",
        to_version="4.1.3",
    )
    result = apply_fix_to_lockfile(lockfile_bytes, candidate)
    assert result is not None
    data = json.loads(result)
    assert data["packages"]["node_modules/ansi-styles"]["version"] == "4.3.0"
    assert data["packages"]["node_modules/chalk"]["version"] == "4.1.3"


# --- GitHub action (11) ---


def test_open_fix_pr_success_returns_opened(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = f"arguss/fix-{candidate.candidate_id}"
    client = _mock_github_client(
        _happy_path_handler("expressjs", "express", branch_name),
    )

    result = open_fix_pr(
        candidate,
        _verdict(candidate),
        _finding(),
        work_tree,
        "expressjs",
        "express",
        _TEST_PAT,
        http_client=client,
    )

    assert result.status == "opened"
    assert result.pr_number == 42
    assert result.pr_url == "https://github.com/expressjs/express/pull/42"
    assert result.reason is None


def test_open_fix_pr_idempotent_when_branch_exists(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = f"arguss/fix-{candidate.candidate_id}"

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        if method == "GET" and f"/branches/{branch_name}" in url:
            return _httpx_response(200, {"name": branch_name})
        if method == "GET" and url.endswith("/pulls"):
            return _httpx_response(
                200,
                [
                    {
                        "html_url": "https://github.com/o/r/pull/40",
                        "number": 40,
                        "head": {"ref": branch_name, "label": f"o:{branch_name}"},
                    },
                ],
            )
        return _httpx_response(500, {"message": "unexpected"})

    result = open_fix_pr(
        candidate,
        _verdict(candidate),
        _finding(),
        work_tree,
        "o",
        "r",
        _TEST_PAT,
        http_client=_mock_github_client(handler),
    )

    assert result.status == "already_exists"
    assert result.pr_number == 40
    assert result.pr_url == "https://github.com/o/r/pull/40"


def test_open_fix_pr_lockfile_modifier_returns_none(
    work_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate()
    monkeypatch.setattr(github_action_mod, "apply_fix_to_lockfile", lambda _b, _c: None)

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        if method == "GET" and "/branches/" in url:
            return _httpx_response(404)
        return _httpx_response(500, {"message": "should not reach"})

    result = open_fix_pr(
        candidate,
        _verdict(candidate),
        _finding(),
        work_tree,
        "o",
        "r",
        _TEST_PAT,
        http_client=_mock_github_client(handler),
    )

    assert result.status == "skipped"
    assert result.reason == "lockfile layout not supported by v1 modifier"


def test_open_fix_pr_github_404_returns_failed(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = f"arguss/fix-{candidate.candidate_id}"

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        if method == "GET" and f"/branches/{branch_name}" in url:
            return _httpx_response(404)
        if method == "GET" and url.endswith("/repos/o/r"):
            return _httpx_response(404, {"message": "Not Found"})
        return _httpx_response(500, {"message": "unexpected"})

    result = open_fix_pr(
        candidate,
        _verdict(candidate),
        _finding(),
        work_tree,
        "o",
        "r",
        _TEST_PAT,
        http_client=_mock_github_client(handler),
    )

    assert result.status == "failed"
    assert result.reason is not None
    assert "Not Found" in result.reason or "404" in result.reason


def test_open_fix_pr_github_409_conflict_returns_failed(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = f"arguss/fix-{candidate.candidate_id}"
    base = _happy_path_handler("o", "r", branch_name)

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        if method == "POST" and url.endswith("/git/refs"):
            return _httpx_response(409, {"message": "Reference already exists"})
        return base(method, url, **kwargs)

    result = open_fix_pr(
        candidate,
        _verdict(candidate),
        _finding(),
        work_tree,
        "o",
        "r",
        _TEST_PAT,
        http_client=_mock_github_client(handler),
    )

    assert result.status == "failed"
    assert result.reason is not None
    assert "create branch" in result.reason


def test_open_fix_pr_github_401_raises_github_action_error(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = f"arguss/fix-{candidate.candidate_id}"

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        if method == "GET" and f"/branches/{branch_name}" in url:
            return _httpx_response(401, {"message": "Bad credentials"})
        return _httpx_response(500, {"message": "unexpected"})

    with pytest.raises(GitHubActionError) as exc_info:
        open_fix_pr(
            candidate,
            _verdict(candidate),
            _finding(),
            work_tree,
            "o",
            "r",
            _TEST_PAT,
            http_client=_mock_github_client(handler),
        )

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


def test_open_fix_pr_branch_name_deterministic() -> None:
    c1 = _candidate()
    c2 = _candidate()
    assert c1.candidate_id == c2.candidate_id
    assert github_action_mod._branch_name(c1) == f"arguss/fix-{c1.candidate_id}"


def test_open_fix_pr_uses_authorization_header(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = f"arguss/fix-{candidate.candidate_id}"
    secret_pat = "ghp_super_secret_unit_test_token"

    with mock.patch.object(github_action_mod, "httpx") as httpx_mod:
        mock_client = _mock_github_client(
            _happy_path_handler("o", "r", branch_name),
        )
        httpx_mod.Client.return_value = mock_client

        open_fix_pr(
            candidate,
            _verdict(candidate),
            _finding(),
            work_tree,
            "o",
            "r",
            secret_pat,
        )

        httpx_mod.Client.assert_called_once()
        call_kwargs = httpx_mod.Client.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"] == f"Bearer {secret_pat}"


def test_open_fix_pr_pat_not_in_logs(
    work_tree: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    candidate = _candidate()
    branch_name = f"arguss/fix-{candidate.candidate_id}"
    secret_pat = "ghp_must_never_appear_in_logs_xyz"

    with caplog.at_level(logging.DEBUG):
        open_fix_pr(
            candidate,
            _verdict(candidate),
            _finding(),
            work_tree,
            "o",
            "r",
            secret_pat,
            http_client=_mock_github_client(
                _happy_path_handler("o", "r", branch_name),
            ),
        )

    for record in caplog.records:
        assert secret_pat not in record.getMessage()
    assert secret_pat not in caplog.text


def test_open_fix_pr_pr_body_includes_candidate_id(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = f"arguss/fix-{candidate.candidate_id}"
    captured: dict[str, Any] = {}

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        if method == "POST" and url.endswith("/pulls"):
            captured["body"] = kwargs.get("json")
            return _httpx_response(
                201,
                {"html_url": "https://github.com/o/r/pull/1", "number": 1},
            )
        return _happy_path_handler("o", "r", branch_name)(method, url, **kwargs)

    open_fix_pr(
        candidate,
        _verdict(candidate),
        _finding(),
        work_tree,
        "o",
        "r",
        _TEST_PAT,
        http_client=_mock_github_client(handler),
    )

    body = captured.get("body")
    assert body is not None
    assert candidate.candidate_id in body["body"]
    assert "GHSA-test" in body["title"]


@mock.patch(
    "arguss.web.github_action.explain_verdict_to_human",
    return_value="This patch is safe because...",
)
def test_open_fix_pr_pr_body_includes_explanation_when_available(
    _mock_explain: mock.MagicMock,
    work_tree: Path,
) -> None:
    candidate = _candidate()
    branch_name = f"arguss/fix-{candidate.candidate_id}"
    captured: dict[str, Any] = {}

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        if method == "POST" and url.endswith("/pulls"):
            captured["body"] = kwargs.get("json")
            return _httpx_response(
                201,
                {"html_url": "https://github.com/o/r/pull/1", "number": 1},
            )
        return _happy_path_handler("o", "r", branch_name)(method, url, **kwargs)

    open_fix_pr(
        candidate,
        _verdict(candidate),
        _finding(),
        work_tree,
        "o",
        "r",
        _TEST_PAT,
        http_client=_mock_github_client(handler),
    )

    body = captured.get("body")
    assert body is not None
    pr_body = body["body"]
    assert "### Context" in pr_body
    assert "This patch is safe because..." in pr_body
    _mock_explain.assert_called_once()


@mock.patch(
    "arguss.web.github_action.explain_verdict_to_human",
    return_value=None,
)
def test_open_fix_pr_pr_body_falls_back_when_explanation_returns_none(
    _mock_explain: mock.MagicMock,
    work_tree: Path,
) -> None:
    candidate = _candidate()
    branch_name = f"arguss/fix-{candidate.candidate_id}"
    captured: dict[str, Any] = {}

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        if method == "POST" and url.endswith("/pulls"):
            captured["body"] = kwargs.get("json")
            return _httpx_response(
                201,
                {"html_url": "https://github.com/o/r/pull/1", "number": 1},
            )
        return _happy_path_handler("o", "r", branch_name)(method, url, **kwargs)

    open_fix_pr(
        candidate,
        _verdict(candidate),
        _finding(),
        work_tree,
        "o",
        "r",
        _TEST_PAT,
        http_client=_mock_github_client(handler),
    )

    body = captured.get("body")
    assert body is not None
    pr_body = body["body"]
    assert "### Context" not in pr_body
    assert "### What this PR does" in pr_body
    assert "### Why the agent is confident" in pr_body
    assert candidate.candidate_id in pr_body
    _mock_explain.assert_called_once()


# --- Endpoint (10) ---


def test_scan_with_action_success_opens_prs_for_auto_merge_only(
    client: TestClient,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "express"
    report = _proposal_report(
        repo,
        (
            _proposal_entry(tier=FixTier.AUTO_MERGE, package="left-pad"),
            _proposal_entry(tier=FixTier.REVIEW_REQUIRED, package="chalk"),
            _proposal_entry(tier=FixTier.DECLINE, package="lodash"),
        ),
    )
    opened = ActionResult(
        candidate_id=report.entries[0].candidate.candidate_id,
        status="opened",
        pr_url="https://github.com/expressjs/express/pull/1",
        pr_number=1,
        reason=None,
    )

    with (
        mock.patch.object(
            routes_mod,
            "shallow_clone",
            side_effect=lambda _url, dest: _mock_clone_with_lockfile(dest),
        ),
        mock.patch.object(routes_mod, "propose_fixes", return_value=report),
        mock.patch.object(routes_mod, "open_fix_pr", return_value=opened) as open_pr,
    ):
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL, "pat": _TEST_PAT},
        )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert len(data["actions"]) == 1
    assert data["actions"][0]["status"] == "opened"
    assert open_pr.call_count == 1
    assert open_pr.call_args.args[0].package == "left-pad"


def test_scan_with_action_review_required_no_pr(
    client: TestClient,
    tmp_path: Path,
) -> None:
    report = _proposal_report(
        tmp_path / "repo",
        (_proposal_entry(tier=FixTier.REVIEW_REQUIRED),),
    )

    with (
        mock.patch.object(
            routes_mod,
            "shallow_clone",
            side_effect=lambda _url, dest: _mock_clone_with_lockfile(dest),
        ),
        mock.patch.object(routes_mod, "propose_fixes", return_value=report),
        mock.patch.object(routes_mod, "open_fix_pr") as open_pr,
    ):
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL, "pat": _TEST_PAT},
        )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["actions"] == []
    open_pr.assert_not_called()


def test_scan_with_action_decline_no_pr(
    client: TestClient,
    tmp_path: Path,
) -> None:
    report = _proposal_report(
        tmp_path / "repo",
        (_proposal_entry(tier=FixTier.DECLINE),),
    )

    with (
        mock.patch.object(
            routes_mod,
            "shallow_clone",
            side_effect=lambda _url, dest: _mock_clone_with_lockfile(dest),
        ),
        mock.patch.object(routes_mod, "propose_fixes", return_value=report),
        mock.patch.object(routes_mod, "open_fix_pr") as open_pr,
    ):
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL, "pat": _TEST_PAT},
        )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["actions"] == []
    open_pr.assert_not_called()


def test_scan_with_action_bad_pat_returns_401(client: TestClient) -> None:
    report = _proposal_report(
        Path("/tmp/repo"),
        (_proposal_entry(tier=FixTier.AUTO_MERGE),),
    )

    with (
        mock.patch.object(
            routes_mod,
            "shallow_clone",
            side_effect=lambda _url, dest: _mock_clone_with_lockfile(dest),
        ),
        mock.patch.object(routes_mod, "propose_fixes", return_value=report),
        mock.patch.object(
            routes_mod,
            "open_fix_pr",
            side_effect=GitHubActionError(
                "check branch: Bad credentials",
                status_code=status.HTTP_401_UNAUTHORIZED,
            ),
        ),
    ):
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL, "pat": "ghp_invalid"},
        )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Invalid or expired PAT"


def test_scan_with_action_pat_lacks_scope_returns_403(client: TestClient) -> None:
    report = _proposal_report(
        Path("/tmp/repo"),
        (_proposal_entry(tier=FixTier.AUTO_MERGE),),
    )

    with (
        mock.patch.object(
            routes_mod,
            "shallow_clone",
            side_effect=lambda _url, dest: _mock_clone_with_lockfile(dest),
        ),
        mock.patch.object(routes_mod, "propose_fixes", return_value=report),
        mock.patch.object(
            routes_mod,
            "open_fix_pr",
            side_effect=GitHubActionError(
                "check branch: Resource not accessible",
                status_code=status.HTTP_403_FORBIDDEN,
            ),
        ),
    ):
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL, "pat": _TEST_PAT},
        )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["detail"] == "PAT lacks repo scope on this repository"


def test_scan_with_action_invalid_url_returns_400(client: TestClient) -> None:
    response = client.post(
        _SCAN_WITH_ACTION,
        json={"url": "https://gitlab.com/o/r", "pat": _TEST_PAT},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "detail" in response.json()


def test_scan_with_action_partial_success_returns_200(
    client: TestClient,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    auto_a = _proposal_entry(tier=FixTier.AUTO_MERGE, package="left-pad")
    auto_b = _proposal_entry(tier=FixTier.AUTO_MERGE, package="chalk")
    report = _proposal_report(repo, (auto_a, auto_b))

    opened = ActionResult(
        candidate_id=auto_a.candidate.candidate_id,
        status="opened",
        pr_url="https://github.com/o/r/pull/1",
        pr_number=1,
        reason=None,
    )
    failed = ActionResult(
        candidate_id=auto_b.candidate.candidate_id,
        status="failed",
        pr_url=None,
        pr_number=None,
        reason="open pull request: merge conflict",
    )

    with (
        mock.patch.object(
            routes_mod,
            "shallow_clone",
            side_effect=lambda _url, dest: _mock_clone_with_lockfile(dest),
        ),
        mock.patch.object(routes_mod, "propose_fixes", return_value=report),
        mock.patch.object(routes_mod, "open_fix_pr", side_effect=[opened, failed]),
    ):
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL, "pat": _TEST_PAT},
        )

    assert response.status_code == status.HTTP_200_OK
    actions = response.json()["actions"]
    assert len(actions) == 2
    assert {a["status"] for a in actions} == {"opened", "failed"}


def test_scan_with_action_pat_in_request_body_not_in_response(
    client: TestClient,
    tmp_path: Path,
) -> None:
    secret_pat = "ghp_response_must_not_echo_this_token"
    report = _proposal_report(
        tmp_path / "repo",
        (_proposal_entry(tier=FixTier.AUTO_MERGE),),
    )

    with (
        mock.patch.object(
            routes_mod,
            "shallow_clone",
            side_effect=lambda _url, dest: _mock_clone_with_lockfile(dest),
        ),
        mock.patch.object(routes_mod, "propose_fixes", return_value=report),
        mock.patch.object(
            routes_mod,
            "open_fix_pr",
            return_value=ActionResult(
                candidate_id=report.entries[0].candidate.candidate_id,
                status="opened",
                pr_url="https://github.com/o/r/pull/1",
                pr_number=1,
                reason=None,
            ),
        ),
    ):
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL, "pat": secret_pat},
        )

    assert response.status_code == status.HTTP_200_OK
    assert secret_pat not in response.text


def test_scan_with_action_response_includes_actions_field(
    client: TestClient,
    tmp_path: Path,
) -> None:
    report = _proposal_report(tmp_path / "repo", ())

    with (
        mock.patch.object(
            routes_mod,
            "shallow_clone",
            side_effect=lambda _url, dest: _mock_clone_with_lockfile(dest),
        ),
        mock.patch.object(routes_mod, "propose_fixes", return_value=report),
    ):
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL, "pat": _TEST_PAT},
        )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert set(data.keys()) == {
        "repo_path",
        "lockfile_path",
        "entries",
        "skipped_findings",
        "summary",
        "actions",
        "executive_summary",
    }
    assert data["actions"] == []


def test_scan_with_action_no_auto_merge_returns_empty_actions(
    client: TestClient,
    tmp_path: Path,
) -> None:
    report = _proposal_report(
        tmp_path / "repo",
        (
            _proposal_entry(tier=FixTier.REVIEW_REQUIRED),
            _proposal_entry(tier=FixTier.DECLINE),
        ),
    )

    with (
        mock.patch.object(
            routes_mod,
            "shallow_clone",
            side_effect=lambda _url, dest: _mock_clone_with_lockfile(dest),
        ),
        mock.patch.object(routes_mod, "propose_fixes", return_value=report),
        mock.patch.object(routes_mod, "open_fix_pr") as open_pr,
    ):
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL, "pat": _TEST_PAT},
        )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["actions"] == []
    open_pr.assert_not_called()


# --- Integration (1) ---


@pytest.mark.integration
def test_scan_with_action_integration_against_fork(
    client: TestClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kill_switch_off: None,
) -> None:
    """Live GitHub: requires ARGUSS_TEST_GITHUB_PAT and ARGUSS_TEST_GITHUB_REPO_URL."""
    pat = os.environ.get("ARGUSS_TEST_GITHUB_PAT")
    repo_url = os.environ.get("ARGUSS_TEST_GITHUB_REPO_URL")
    if not pat or not repo_url:
        pytest.skip(
            "Set ARGUSS_TEST_GITHUB_PAT and ARGUSS_TEST_GITHUB_REPO_URL "
            "to run live Mode C integration (opens real PRs on your fork)"
        )

    parsed = parse_github_url(repo_url)
    db = tmp_path / "scan_with_action_integration.db"
    monkeypatch.setattr(live_settings, "db_path", db)
    monkeypatch.setattr(Settings, "db_path", db)

    response = client.post(
        _SCAN_WITH_ACTION,
        json={"url": repo_url, "pat": pat},
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "actions" in data
    assert isinstance(data["actions"], list)
    assert parsed.owner in repo_url
