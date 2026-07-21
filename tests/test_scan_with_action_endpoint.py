"""Tests for lockfile fix, GitHub action, and POST /scan/with-action (Mode C)."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

import httpx
import pytest
from fastapi import HTTPException, status
from fastapi.testclient import TestClient

import arguss.web.github_action as github_action_mod
import arguss.web.mode_c_workflow as mode_c_mod
import arguss.web.routes as routes_mod
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
from arguss.web.action_runs import load_action_run
from arguss.web.github_action import (
    ActionResult,
    GitHubActionError,
    open_fix_pr,
    run_mode_c_actions,
)
from arguss.web.github_url import parse_github_url
from arguss.web.lockfile_fix import (
    FixApplicationResult,
    LockfileModificationError,
    apply_fix_to_lockfile,
    parse_lockfile_bytes,
)
from arguss.web.mode_c_workflow import ScanWithActionResult
from tests.web.session_helpers import make_session_client, seed_github_installation

_SCAN_WITH_ACTION = "/scan/with-action"


def _scan_action_result(
    report: ProposalReport,
    actions: list[ActionResult],
) -> ScanWithActionResult:
    from arguss.core.serialization import proposal_report_with_actions_payload

    acts = list(actions)
    payload = proposal_report_with_actions_payload(report, acts)
    payload["executive_summary"] = None
    return ScanWithActionResult(
        report=report,
        actions=acts,
        payload={**payload, "action_run_id": "00000000-0000-4000-8000-000000000001"},
        scan_hash="test-scan-hash",
        action_run_id="00000000-0000-4000-8000-000000000001",
    )


_EXPRESS_URL = "https://github.com/expressjs/express"
_TEST_INSTALLATION_ID = 12345
_TEST_APP_TOKEN = "ghs_test_installation_token_for_unit_tests"
_INTERNAL_DETAIL = "Internal error during analysis"
_FIXTURES = Path(__file__).parent / "fixtures" / "lockfiles"
_FIXED_TIME = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def kill_switch_off(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("ARGUSS_KILL_SWITCH", raising=False)
    monkeypatch.setenv("ARGUSS_KILL_SWITCH_FILE_PATH", str(tmp_path / "kill_switch_absent"))


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Session-enabled client with a verified installation id already bound.

    The JSON Mode C endpoints no longer accept installation_id in the body;
    they require the OAuth-verified session, same as the browser path.
    """
    session_client = make_session_client(monkeypatch)
    seed_github_installation(session_client, _TEST_INSTALLATION_ID)
    return session_client


@pytest.fixture
def no_session_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Session-enabled client with NO verified installation id bound."""
    return make_session_client(monkeypatch)


@pytest.fixture
def work_tree(tmp_path: Path) -> Path:
    lockfile = _FIXTURES / "minimal.json"
    (tmp_path / "package-lock.json").write_bytes(lockfile.read_bytes())
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "minimal-test",
                "version": "1.0.0",
                "dependencies": {"left-pad": "1.3.0"},
            },
        )
        + "\n",
        encoding="utf-8",
    )
    return tmp_path


def _mock_npm_client() -> mock.MagicMock:
    client = mock.MagicMock()
    client.fetch_version_metadata.return_value = {
        "dist": {
            "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.1.tgz",
            "integrity": "sha512-testintegrity",
        },
    }
    return client


def _candidate(
    *,
    package: str = "left-pad",
    from_version: str = "1.3.0",
    to_version: str = "1.3.1",
    fix_kind: FixKind = FixKind.PATCH,
    source_finding_ids: tuple[str, ...] = ("GHSA-test",),
    repo_id: str = "/tmp/repo",
) -> FixCandidate:
    return FixCandidate(
        package=package,
        from_version=from_version,
        to_version=to_version,
        fix_kind=fix_kind,
        source_finding_ids=source_finding_ids,
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

    def _dispatch(method: str, url: str, **kwargs: Any) -> httpx.Response:
        return handler(method, url, **kwargs)

    client.request.side_effect = _dispatch
    client.get.side_effect = lambda url, **kwargs: _dispatch("GET", url, **kwargs)
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
        if method == "GET" and "contents/package-lock.json" in url:
            return _httpx_response(
                200,
                {"sha": "abc123", "content": "e30=", "encoding": "base64"},
            )
        if method == "GET" and "contents/package.json" in url:
            return _httpx_response(
                200,
                {"sha": "def456", "content": "e30=", "encoding": "base64"},
            )
        if method == "PUT" and "contents/package-lock.json" in url:
            return _httpx_response(200, {"commit": {"sha": "lockfile-commit-sha"}})
        if method == "PUT" and "contents/package.json" in url:
            return _httpx_response(200, {"commit": {"sha": "package-json-commit-sha"}})
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
    return ProposalEntry(
        finding=finding, related_findings=(finding,), candidate=candidate, verdict=verdict
    )


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


# --- Lockfile modifier (integration smoke) ---


def test_apply_fix_simple_direct_dep_integration() -> None:
    lockfile = parse_lockfile_bytes((_FIXTURES / "minimal.json").read_bytes())
    package_json = {
        "name": "minimal-test",
        "version": "1.0.0",
        "dependencies": {"left-pad": "1.3.0"},
    }
    candidate = _candidate()
    npm = _mock_npm_client()
    npm.fetch_version_metadata.return_value = {
        "dist": {
            "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.1.tgz",
            "integrity": "sha512-testintegrity",
        },
    }

    result = apply_fix_to_lockfile(lockfile, package_json, candidate, npm)

    assert result.applied is True
    assert lockfile["packages"]["node_modules/left-pad"]["version"] == "1.3.1"
    assert lockfile["packages"][""]["dependencies"]["left-pad"] == "1.3.1"


def test_apply_fix_top_level_direct_with_transitive_children() -> None:
    lockfile = parse_lockfile_bytes((_FIXTURES / "with-transitive.json").read_bytes())
    package_json = {"dependencies": {"chalk": "^4.1.2"}}
    candidate = _candidate(
        package="chalk",
        from_version="4.1.2",
        to_version="4.1.3",
        source_finding_ids=("GHSA-chalk",),
    )
    npm = mock.MagicMock()
    npm.fetch_version_metadata.return_value = {
        "dist": {
            "tarball": "https://registry.npmjs.org/chalk/-/chalk-4.1.3.tgz",
            "integrity": "sha512-chalk",
        },
    }

    result = apply_fix_to_lockfile(lockfile, package_json, candidate, npm)

    assert result.applied is True
    assert lockfile["packages"]["node_modules/chalk"]["version"] == "4.1.3"
    assert package_json["dependencies"]["chalk"] == "^4.1.3"


def test_apply_fix_sets_integrity_from_registry() -> None:
    lockfile = parse_lockfile_bytes((_FIXTURES / "minimal.json").read_bytes())
    package_json = {"dependencies": {"left-pad": "1.3.0"}}
    candidate = _candidate()
    npm = _mock_npm_client()

    result = apply_fix_to_lockfile(lockfile, package_json, candidate, npm)

    assert result.applied is True
    entry = lockfile["packages"]["node_modules/left-pad"]
    assert entry["integrity"] == "sha512-testintegrity"


def test_apply_fix_updates_resolved_url() -> None:
    lockfile = parse_lockfile_bytes((_FIXTURES / "minimal.json").read_bytes())
    package_json = {"dependencies": {"left-pad": "1.3.0"}}
    candidate = _candidate()
    npm = _mock_npm_client()

    result = apply_fix_to_lockfile(lockfile, package_json, candidate, npm)

    assert result.applied is True
    resolved = lockfile["packages"]["node_modules/left-pad"]["resolved"]
    assert "left-pad-1.3.1.tgz" in resolved
    assert "1.3.0" not in resolved


def test_apply_fix_version_mismatch_skips() -> None:
    lockfile = parse_lockfile_bytes((_FIXTURES / "minimal.json").read_bytes())
    package_json = {"dependencies": {"left-pad": "1.3.0"}}
    candidate = _candidate(from_version="9.9.9")
    npm = _mock_npm_client()

    result = apply_fix_to_lockfile(lockfile, package_json, candidate, npm)

    assert result.applied is False


def test_apply_fix_nested_direct_dep_succeeds() -> None:
    lockfile = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"foo": "1.0.0"}},
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
    package_json = {"dependencies": {"foo": "1.0.0"}}
    candidate = _candidate(package="foo", from_version="1.0.0", to_version="1.0.1")
    npm = mock.MagicMock()
    npm.fetch_version_metadata.return_value = {
        "dist": {
            "tarball": "https://registry.npmjs.org/foo/-/foo-1.0.1.tgz",
            "integrity": "sha512-foo",
        },
    }

    result = apply_fix_to_lockfile(lockfile, package_json, candidate, npm)

    assert result.applied is True
    assert lockfile["packages"]["node_modules/foo"]["version"] == "1.0.1"


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
    package_json = {"dependencies": {"@scope/pkg": "1.0.0"}}
    candidate = _candidate(
        package="@scope/pkg",
        from_version="1.0.0",
        to_version="1.0.1",
    )
    npm = mock.MagicMock()
    npm.fetch_version_metadata.return_value = {
        "dist": {
            "tarball": "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.1.tgz",
            "integrity": "sha512-scoped",
        },
    }

    result = apply_fix_to_lockfile(lockfile, package_json, candidate, npm)

    assert result.applied is True
    entry = lockfile["packages"]["node_modules/@scope/pkg"]
    assert entry["version"] == "1.0.1"
    assert "1.0.1" in entry["resolved"]


def test_apply_fix_malformed_lockfile_raises() -> None:
    with pytest.raises(LockfileModificationError, match="not valid JSON"):
        parse_lockfile_bytes(b"{not json")


def test_apply_fix_preserves_other_packages() -> None:
    lockfile = parse_lockfile_bytes((_FIXTURES / "with-transitive.json").read_bytes())
    package_json = {"dependencies": {"chalk": "^4.1.2"}}
    candidate = _candidate(
        package="chalk",
        from_version="4.1.2",
        to_version="4.1.3",
    )
    npm = mock.MagicMock()
    npm.fetch_version_metadata.return_value = {
        "dist": {
            "tarball": "https://registry.npmjs.org/chalk/-/chalk-4.1.3.tgz",
            "integrity": "sha512-chalk",
        },
    }

    result = apply_fix_to_lockfile(lockfile, package_json, candidate, npm)

    assert result.applied is True
    assert lockfile["packages"]["node_modules/ansi-styles"]["version"] == "4.3.0"
    assert lockfile["packages"]["node_modules/chalk"]["version"] == "4.1.3"


# --- GitHub action (11) ---


def test_open_fix_pr_opened_includes_head_sha_from_put(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = github_action_mod._derive_branch_name(candidate)
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
        _TEST_INSTALLATION_ID,
        http_client=client,
        npm_client=_mock_npm_client(),
    )

    assert result.status == "opened"
    assert result.head_sha == "lockfile-commit-sha"


def test_open_fix_pr_already_exists_includes_head_sha(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = github_action_mod._derive_branch_name(candidate)

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
        if method == "GET" and url.endswith("/pulls/40"):
            return _httpx_response(200, {"head": {"sha": "existing-head-sha"}})
        return _httpx_response(500, {"message": "unexpected"})

    result = open_fix_pr(
        candidate,
        _verdict(candidate),
        _finding(),
        work_tree,
        "o",
        "r",
        _TEST_INSTALLATION_ID,
        http_client=_mock_github_client(handler),
        npm_client=_mock_npm_client(),
    )

    assert result.status == "already_exists"
    assert result.head_sha == "existing-head-sha"


def test_open_fix_pr_resume_fetches_head_sha(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = github_action_mod._derive_branch_name(candidate)
    base = _happy_path_handler("o", "r", branch_name)

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        if method == "GET" and f"/branches/{branch_name}" in url:
            return _httpx_response(200, {"name": branch_name})
        if method == "GET" and url.endswith("/pulls") and kwargs.get("params"):
            return _httpx_response(200, [])
        if method == "POST" and url.endswith("/pulls"):
            return _httpx_response(
                201,
                {
                    "html_url": "https://github.com/o/r/pull/55",
                    "number": 55,
                },
            )
        if method == "GET" and url.endswith("/pulls/55"):
            return _httpx_response(200, {"head": {"sha": "resume-head-sha"}})
        return base(method, url, **kwargs)

    result = open_fix_pr(
        candidate,
        _verdict(candidate),
        _finding(),
        work_tree,
        "o",
        "r",
        _TEST_INSTALLATION_ID,
        http_client=_mock_github_client(handler),
        npm_client=_mock_npm_client(),
    )

    assert result.status == "opened"
    assert result.head_sha == "resume-head-sha"


def test_open_fix_pr_success_returns_opened(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = github_action_mod._derive_branch_name(candidate)
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
        _TEST_INSTALLATION_ID,
        http_client=client,
        npm_client=_mock_npm_client(),
    )

    assert result.status == "opened"
    assert result.pr_number == 42
    assert result.pr_url == "https://github.com/expressjs/express/pull/42"
    assert result.reason is None


def test_open_fix_pr_idempotent_when_branch_exists(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = github_action_mod._derive_branch_name(candidate)

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
        _TEST_INSTALLATION_ID,
        http_client=_mock_github_client(handler),
        npm_client=_mock_npm_client(),
    )

    assert result.status == "already_exists"
    assert result.pr_number == 40
    assert result.pr_url == "https://github.com/o/r/pull/40"


def test_open_fix_pr_lockfile_modifier_returns_none(
    work_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate()
    monkeypatch.setattr(
        github_action_mod,
        "apply_fix_to_lockfile",
        lambda *_a, **_k: FixApplicationResult(
            applied=False,
            skipped_reason="lockfile layout not supported",
        ),
    )

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
        _TEST_INSTALLATION_ID,
        http_client=_mock_github_client(handler),
        npm_client=_mock_npm_client(),
    )

    assert result.status == "skipped"
    assert result.reason == "lockfile layout not supported"


def test_open_fix_pr_github_404_returns_failed(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = github_action_mod._derive_branch_name(candidate)

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
        _TEST_INSTALLATION_ID,
        http_client=_mock_github_client(handler),
        npm_client=_mock_npm_client(),
    )

    assert result.status == "failed"
    assert result.reason is not None
    assert "Not Found" in result.reason or "404" in result.reason


def test_open_fix_pr_github_409_conflict_returns_failed(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = github_action_mod._derive_branch_name(candidate)
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
        _TEST_INSTALLATION_ID,
        http_client=_mock_github_client(handler),
        npm_client=_mock_npm_client(),
    )

    assert result.status == "failed"
    assert result.reason is not None
    assert "create branch" in result.reason


def test_open_fix_pr_github_401_raises_github_action_error(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = github_action_mod._derive_branch_name(candidate)

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
            _TEST_INSTALLATION_ID,
            http_client=_mock_github_client(handler),
            npm_client=_mock_npm_client(),
        )

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


def test_open_fix_pr_branch_name_deterministic() -> None:
    c1 = _candidate(package="left-pad", from_version="1.3.0", to_version="1.3.1")
    c2 = _candidate(package="left-pad", from_version="1.3.0", to_version="1.3.1")
    expected = "arguss/upgrade-left-pad-1.3.0-to-1.3.1"
    assert github_action_mod._derive_branch_name(c1) == expected
    assert github_action_mod._derive_branch_name(c2) == expected


def test_open_fix_pr_uses_authorization_header(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = github_action_mod._derive_branch_name(candidate)

    with (
        mock.patch.object(
            github_action_mod,
            "get_installation_access_token",
            return_value=_TEST_APP_TOKEN,
        ) as mint_token,
        mock.patch.object(github_action_mod, "httpx") as httpx_mod,
    ):
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
            _TEST_INSTALLATION_ID,
            npm_client=_mock_npm_client(),
        )

        mint_token.assert_called_once_with(_TEST_INSTALLATION_ID)
        httpx_mod.Client.assert_called_once()
        call_kwargs = httpx_mod.Client.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"] == f"Bearer {_TEST_APP_TOKEN}"


def test_open_fix_pr_token_not_in_logs(
    work_tree: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    candidate = _candidate()
    branch_name = github_action_mod._derive_branch_name(candidate)
    secret_token = "ghs_must_never_appear_in_logs_xyz"

    with (
        mock.patch.object(
            github_action_mod,
            "get_installation_access_token",
            return_value=secret_token,
        ),
        caplog.at_level(logging.DEBUG),
    ):
        open_fix_pr(
            candidate,
            _verdict(candidate),
            _finding(),
            work_tree,
            "o",
            "r",
            _TEST_INSTALLATION_ID,
            http_client=_mock_github_client(
                _happy_path_handler("o", "r", branch_name),
            ),
            npm_client=_mock_npm_client(),
        )

    for record in caplog.records:
        assert secret_token not in record.getMessage()
    assert secret_token not in caplog.text


def test_open_fix_pr_pr_body_includes_candidate_id(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = github_action_mod._derive_branch_name(candidate)
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
        _TEST_INSTALLATION_ID,
        http_client=_mock_github_client(handler),
        npm_client=_mock_npm_client(),
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
    branch_name = github_action_mod._derive_branch_name(candidate)
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
        _TEST_INSTALLATION_ID,
        http_client=_mock_github_client(handler),
        npm_client=_mock_npm_client(),
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
    branch_name = github_action_mod._derive_branch_name(candidate)
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
        _TEST_INSTALLATION_ID,
        http_client=_mock_github_client(handler),
        npm_client=_mock_npm_client(),
    )

    body = captured.get("body")
    assert body is not None
    pr_body = body["body"]
    assert "### Context" not in pr_body
    assert "### What this PR does" in pr_body
    assert "### Why the agent is confident" in pr_body
    assert candidate.candidate_id in pr_body
    _mock_explain.assert_called_once()


def test_open_fix_pr_put_includes_fetched_sha(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = github_action_mod._derive_branch_name(candidate)
    put_bodies: list[dict[str, Any]] = []

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        if method == "PUT" and "contents/package-lock.json" in url:
            body = kwargs.get("json")
            if isinstance(body, dict):
                put_bodies.append(body)
        return _happy_path_handler("o", "r", branch_name)(method, url, **kwargs)

    result = open_fix_pr(
        candidate,
        _verdict(candidate),
        _finding(),
        work_tree,
        "o",
        "r",
        _TEST_INSTALLATION_ID,
        http_client=_mock_github_client(handler),
        npm_client=_mock_npm_client(),
    )

    assert result.status == "opened"
    assert put_bodies
    assert put_bodies[0].get("sha") == "abc123"


def test_open_fix_pr_put_409_returns_review_required_reason(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = github_action_mod._derive_branch_name(candidate)
    base = _happy_path_handler("o", "r", branch_name)

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        if method == "PUT" and "contents/package-lock.json" in url:
            return _httpx_response(409, {"message": "sha conflict"})
        return base(method, url, **kwargs)

    result = open_fix_pr(
        candidate,
        _verdict(candidate),
        _finding(),
        work_tree,
        "o",
        "r",
        _TEST_INSTALLATION_ID,
        http_client=_mock_github_client(handler),
        npm_client=_mock_npm_client(),
    )

    assert result.status == "failed"
    assert result.reason is not None
    assert "manual review required" in result.reason


def test_open_fix_pr_lockfile_missing_on_branch_returns_failed(work_tree: Path) -> None:
    candidate = _candidate()
    branch_name = github_action_mod._derive_branch_name(candidate)
    base = _happy_path_handler("o", "r", branch_name)

    def handler(method: str, url: str, **kwargs: Any) -> httpx.Response:
        if method == "GET" and "contents/package-lock.json" in url:
            return _httpx_response(404, {"message": "Not Found"})
        return base(method, url, **kwargs)

    result = open_fix_pr(
        candidate,
        _verdict(candidate),
        _finding(),
        work_tree,
        "o",
        "r",
        _TEST_INSTALLATION_ID,
        http_client=_mock_github_client(handler),
        npm_client=_mock_npm_client(),
    )

    assert result.status == "failed"
    assert result.reason is not None
    assert "not found on branch" in result.reason


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
            "execute_scan_with_action",
            return_value=_scan_action_result(report, [opened]),
        ) as run_actions,
    ):
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL},
        )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert len(data["actions"]) == 1
    assert data["actions"][0]["status"] == "opened"
    assert run_actions.call_count == 1
    assert run_actions.call_args.kwargs["url"] == _EXPRESS_URL
    # The installation id comes from the verified session, not the body.
    assert run_actions.call_args.kwargs["installation_id"] == _TEST_INSTALLATION_ID


def test_scan_with_action_without_session_is_rejected(
    no_session_client: TestClient,
    tmp_path: Path,
) -> None:
    """No verified session: 401, no token minted, no scan started."""
    execute = mock.AsyncMock()
    with mock.patch.object(routes_mod, "execute_scan_with_action", execute):
        response = no_session_client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL},
        )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "GitHub App installation" in response.json()["detail"]
    execute.assert_not_called()


def test_scan_with_action_start_without_session_is_rejected(
    no_session_client: TestClient,
) -> None:
    run = mock.AsyncMock()
    with mock.patch.object(routes_mod, "run_scan_background", run):
        response = no_session_client.post(
            "/scan/with-action/start",
            json={"url": _EXPRESS_URL},
        )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    run.assert_not_called()


def test_scan_with_action_body_installation_id_is_ignored(
    client: TestClient,
    tmp_path: Path,
) -> None:
    """A body-supplied installation_id never reaches token minting."""
    report = _proposal_report(tmp_path / "repo", ())
    with mock.patch.object(
        routes_mod, "execute_scan_with_action", return_value=_scan_action_result(report, [])
    ) as run_actions:
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL, "installation_id": 666666},
        )

    assert response.status_code == status.HTTP_200_OK
    # The session id (seeded fixture) wins; the body value is discarded.
    assert run_actions.call_args.kwargs["installation_id"] == _TEST_INSTALLATION_ID


def test_scan_with_action_start_body_installation_id_is_ignored(
    client: TestClient,
) -> None:
    captured: dict[str, object] = {}

    async def fake_background(scan_id: str, **kwargs: object) -> None:
        captured.update(kwargs)

    with mock.patch.object(
        routes_mod,
        "run_scan_background",
        new_callable=mock.AsyncMock,
        side_effect=fake_background,
    ):
        response = client.post(
            "/scan/with-action/start",
            json={"url": _EXPRESS_URL, "installation_id": 666666},
        )

    assert response.status_code == status.HTTP_200_OK
    assert captured["installation_id"] == _TEST_INSTALLATION_ID


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
            routes_mod, "execute_scan_with_action", return_value=_scan_action_result(report, [])
        ) as run_actions,
    ):
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL},
        )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["actions"] == []
    run_actions.assert_called_once()


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
            routes_mod, "execute_scan_with_action", return_value=_scan_action_result(report, [])
        ) as run_actions,
    ):
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL},
        )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["actions"] == []
    run_actions.assert_called_once()


def test_scan_with_action_bad_app_auth_returns_401(client: TestClient) -> None:
    detail = "GitHub App authorization failed; reconnect arguss-bot and retry"
    with (
        mock.patch.object(
            routes_mod,
            "execute_scan_with_action",
            side_effect=HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=detail,
            ),
        ),
    ):
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL},
        )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == detail


def test_scan_with_action_no_repo_access_returns_403(client: TestClient) -> None:
    detail = "arguss-bot does not have access to this repository"
    with (
        mock.patch.object(
            routes_mod,
            "execute_scan_with_action",
            side_effect=HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=detail,
            ),
        ),
    ):
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL},
        )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["detail"] == detail


def test_scan_with_action_invalid_url_returns_400(client: TestClient) -> None:
    response = client.post(
        _SCAN_WITH_ACTION,
        json={"url": "https://gitlab.com/o/r"},
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
            "execute_scan_with_action",
            return_value=_scan_action_result(report, [opened, failed]),
        ),
    ):
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL},
        )

    assert response.status_code == status.HTTP_200_OK
    actions = response.json()["actions"]
    assert len(actions) == 2
    assert {a["status"] for a in actions} == {"opened", "failed"}


def test_scan_with_action_response_has_no_authorization_header(
    client: TestClient,
    tmp_path: Path,
) -> None:
    report = _proposal_report(
        tmp_path / "repo",
        (_proposal_entry(tier=FixTier.AUTO_MERGE),),
    )

    with (
        mock.patch.object(
            routes_mod,
            "execute_scan_with_action",
            return_value=_scan_action_result(
                report,
                [
                    ActionResult(
                        candidate_id=report.entries[0].candidate.candidate_id,
                        status="opened",
                        pr_url="https://github.com/o/r/pull/1",
                        pr_number=1,
                        reason=None,
                    )
                ],
            ),
        ),
    ):
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL},
        )

    assert response.status_code == status.HTTP_200_OK
    assert "Authorization" not in response.text
    assert "ghs_" not in response.text
    assert _TEST_APP_TOKEN not in response.text


def test_scan_with_action_response_includes_actions_field(
    client: TestClient,
    tmp_path: Path,
) -> None:
    report = _proposal_report(tmp_path / "repo", ())

    with (
        mock.patch.object(
            routes_mod, "execute_scan_with_action", return_value=_scan_action_result(report, [])
        ),
    ):
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL},
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
        "project_scores",
        "lens_explain",
        "action_run_id",
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
            routes_mod, "execute_scan_with_action", return_value=_scan_action_result(report, [])
        ) as run_actions,
    ):
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL},
        )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["actions"] == []
    run_actions.assert_called_once()


# --- Integration (1) ---


@pytest.mark.integration
def test_scan_with_action_integration_against_fork(
    client: TestClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kill_switch_off: None,
) -> None:
    """Live GitHub: requires ARGUSS_TEST_GITHUB_INSTALLATION_ID and ARGUSS_TEST_GITHUB_REPO_URL."""
    installation_id_raw = os.environ.get("ARGUSS_TEST_GITHUB_INSTALLATION_ID")
    repo_url = os.environ.get("ARGUSS_TEST_GITHUB_REPO_URL")
    if not installation_id_raw or not repo_url:
        pytest.skip(
            "Set ARGUSS_TEST_GITHUB_INSTALLATION_ID and ARGUSS_TEST_GITHUB_REPO_URL "
            "to run live Mode C integration (opens real PRs on your fork)"
        )
    installation_id = int(installation_id_raw)

    parsed = parse_github_url(repo_url)
    db = tmp_path / "scan_with_action_integration.db"
    monkeypatch.setattr(live_settings, "db_path", db)
    monkeypatch.setattr(Settings, "db_path", db)

    # The endpoint reads the installation id from the verified session, not the
    # body; bind the real env-provided id the same way the OAuth callback would.
    seed_github_installation(client, installation_id)
    response = client.post(_SCAN_WITH_ACTION, json={"url": repo_url})

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "actions" in data
    assert isinstance(data["actions"], list)
    assert parsed.owner in repo_url


def test_pr_body_includes_lockfile_only_disclaimer_for_transitive() -> None:
    candidate = _candidate()
    body = github_action_mod._render_pr_body(
        candidate,
        _verdict(candidate),
        _finding(),
        files_modified=("package-lock.json",),
    )
    assert "lockfile-only" in body.lower()
    assert "transitive" in body.lower()


def test_pr_body_no_disclaimer_for_direct_dep_fix() -> None:
    candidate = _candidate()
    body = github_action_mod._render_pr_body(
        candidate,
        _verdict(candidate),
        _finding(),
        files_modified=("package.json", "package-lock.json"),
    )
    assert "lockfile-only" not in body.lower()


@pytest.mark.asyncio
async def test_actions_run_concurrently_with_semaphore(
    work_tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import threading
    import time

    monkeypatch.setattr(github_action_mod.settings, "mode_c_concurrency", 5)
    n = 12
    entries = tuple(_proposal_entry(tier=FixTier.AUTO_MERGE, package=f"pkg-{i}") for i in range(n))
    in_flight = 0
    max_in_flight = 0
    lock = threading.Lock()

    def slow_open(candidate: FixCandidate, *_args: object, **_kwargs: object) -> ActionResult:
        nonlocal in_flight, max_in_flight
        with lock:
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
        time.sleep(0.05)
        with lock:
            in_flight -= 1
        candidate_id = candidate.candidate_id
        return ActionResult(
            candidate_id=candidate_id,
            status="opened",
            pr_url="https://github.com/o/r/pull/1",
            pr_number=1,
            reason=None,
        )

    with (
        mock.patch.object(github_action_mod, "open_fix_pr", side_effect=slow_open),
    ):
        started = time.perf_counter()
        results = await run_mode_c_actions(entries, work_tree, "o", "r", _TEST_INSTALLATION_ID)
        elapsed = time.perf_counter() - started

    assert len(results) == n
    assert max_in_flight <= 5
    assert elapsed < n * 0.05 * 0.75


@pytest.mark.asyncio
async def test_action_failure_does_not_abort_batch(work_tree: Path) -> None:
    entries = tuple(_proposal_entry(tier=FixTier.AUTO_MERGE, package=f"pkg-{i}") for i in range(4))
    opened = ActionResult(
        candidate_id=entries[0].candidate.candidate_id,
        status="opened",
        pr_url="https://github.com/o/r/pull/1",
        pr_number=1,
        reason=None,
    )
    failed = ActionResult(
        candidate_id=entries[1].candidate.candidate_id,
        status="failed",
        pr_url=None,
        pr_number=None,
        reason="boom",
    )

    def side_effect(candidate: FixCandidate, *_a: object, **_kwargs: object) -> ActionResult:
        if candidate.candidate_id == entries[1].candidate.candidate_id:
            raise RuntimeError("simulated failure")
        if candidate.candidate_id == entries[0].candidate.candidate_id:
            return opened
        return failed

    with (
        mock.patch.object(github_action_mod, "open_fix_pr", side_effect=side_effect),
    ):
        results = await run_mode_c_actions(entries, work_tree, "o", "r", _TEST_INSTALLATION_ID)

    assert len(results) == 4
    assert results[1].status == "failed"
    assert results[1].reason == "simulated failure"


@pytest.mark.asyncio
async def test_event_emitter_invoked_for_each_action(work_tree: Path) -> None:
    entries = (
        _proposal_entry(tier=FixTier.AUTO_MERGE, package="left-pad"),
        _proposal_entry(tier=FixTier.AUTO_MERGE, package="chalk"),
    )
    opened = ActionResult(
        candidate_id=entries[0].candidate.candidate_id,
        status="opened",
        pr_url=None,
        pr_number=None,
        reason=None,
    )
    events: list[str] = []

    async def emit(event: dict[str, object]) -> None:
        events.append(str(event.get("type")))

    with (
        mock.patch.object(github_action_mod, "open_fix_pr", return_value=opened),
    ):
        await run_mode_c_actions(
            entries,
            work_tree,
            "o",
            "r",
            _TEST_INSTALLATION_ID,
            event_emitter=emit,
        )

    assert events.count("action_started") == 2
    assert events.count("action_completed") == 2
    assert "actions_planned" in events
    assert "scan_complete" in events


def test_api_ref_reaches_execute_scan_with_action(client: TestClient, tmp_path: Path) -> None:
    report = _proposal_report(tmp_path / "r", (_proposal_entry(tier=FixTier.AUTO_MERGE),))
    with mock.patch.object(
        routes_mod, "execute_scan_with_action", return_value=_scan_action_result(report, [])
    ) as run:
        response = client.post(
            _SCAN_WITH_ACTION,
            json={"url": _EXPRESS_URL, "ref": "v1.0.0"},
        )
    assert response.status_code == status.HTTP_200_OK
    assert run.call_args.kwargs["ref"] == "v1.0.0"


def test_api_default_ref_is_head(client: TestClient, tmp_path: Path) -> None:
    report = _proposal_report(tmp_path / "r", (_proposal_entry(tier=FixTier.AUTO_MERGE),))
    with mock.patch.object(
        routes_mod, "execute_scan_with_action", return_value=_scan_action_result(report, [])
    ) as run:
        client.post(_SCAN_WITH_ACTION, json={"url": _EXPRESS_URL})
    assert run.call_args.kwargs["ref"] == "HEAD"


@pytest.mark.asyncio
async def test_execute_scan_with_action_spawns_merge_task(
    work_tree: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import arguss.web.action_merge as merge_mod

    report = _proposal_report(
        work_tree,
        (_proposal_entry(tier=FixTier.AUTO_MERGE, package="left-pad"),),
    )
    opened = ActionResult(
        candidate_id=report.entries[0].candidate.candidate_id,
        status="opened",
        pr_url="https://github.com/o/r/pull/1",
        pr_number=1,
        reason=None,
        head_sha="abc123",
    )

    monkeypatch.setattr(mode_c_mod.settings, "db_path", tmp_path / "scan.db")

    with (
        mock.patch.object(mode_c_mod, "shallow_clone", return_value=work_tree),
        mock.patch.object(mode_c_mod, "propose_fixes", return_value=report),
        mock.patch.object(mode_c_mod, "run_mode_c_actions", return_value=[opened]),
        mock.patch.object(mode_c_mod, "save_scan_inputs"),
        mock.patch.object(mode_c_mod, "scan_input_hash", side_effect=lambda _p: "hash"),
        mock.patch.object(
            merge_mod, "run_action_merge_task", new_callable=mock.AsyncMock
        ) as merge_task,
    ):
        result = await mode_c_mod.execute_scan_with_action(
            url=_EXPRESS_URL, installation_id=_TEST_INSTALLATION_ID
        )
        await asyncio.sleep(0)

    assert result.action_run_id is not None
    merge_task.assert_called_once()
    assert merge_task.call_args.args[3] == _TEST_INSTALLATION_ID
    loaded = load_action_run(result.action_run_id, tmp_path / "scan.db")
    assert loaded is not None
    assert len(loaded.candidates) == 1
    assert loaded.candidates[0].head_sha == "abc123"
    # Persisted row and spawn task agree on the same installation id.
    assert loaded.installation_id == str(_TEST_INSTALLATION_ID)
    assert loaded.installation_id == str(merge_task.call_args.args[3])


def test_mode_c_create_path_does_not_invent_installation_id() -> None:
    """Create path must thread installation_id — no env read or hardcoded producer."""
    source = Path("arguss/web/mode_c_workflow.py").read_text(encoding="utf-8")
    assert "ARGUSS_GITHUB_APP_INSTALLATION" not in source
    assert "os.environ" not in source
    # create_action_run must receive the threaded installation_id kwarg.
    assert "installation_id=str(installation_id)" in source


@pytest.mark.asyncio
async def test_execute_scan_with_action_creates_completed_run_without_mergeable(
    work_tree: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import arguss.web.action_merge as merge_mod

    report = _proposal_report(work_tree, (_proposal_entry(tier=FixTier.REVIEW_REQUIRED),))
    monkeypatch.setattr(mode_c_mod.settings, "db_path", tmp_path / "scan.db")

    with (
        mock.patch.object(mode_c_mod, "shallow_clone", return_value=work_tree),
        mock.patch.object(mode_c_mod, "propose_fixes", return_value=report),
        mock.patch.object(mode_c_mod, "run_mode_c_actions", return_value=[]),
        mock.patch.object(mode_c_mod, "save_scan_inputs"),
        mock.patch.object(mode_c_mod, "scan_input_hash", side_effect=lambda _p: "hash"),
        mock.patch.object(
            merge_mod, "run_action_merge_task", new_callable=mock.AsyncMock
        ) as merge_task,
    ):
        result = await mode_c_mod.execute_scan_with_action(
            url=_EXPRESS_URL, installation_id=_TEST_INSTALLATION_ID
        )

    assert result.action_run_id is None
    merge_task.assert_not_called()
