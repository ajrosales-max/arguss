"""Tests for GitHub URL parsing, shallow clone, and POST /scan/url."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest import mock

import pytest
from fastapi import HTTPException, status
from fastapi.testclient import TestClient

import arguss.web.git_clone as git_clone_mod
import arguss.web.routes as routes_mod
from arguss.api import app as api_app
from arguss.core.parser import ParserError
from arguss.engine.propose import ProposalReport, ProposalSummary
from arguss.lenses._zizmor_client import ZizmorClientError
from arguss.settings import Settings
from arguss.settings import settings as live_settings
from arguss.web.git_clone import GitCloneError, shallow_clone
from arguss.web.github_fetch import GitHubFetchError, RepoInputs
from arguss.web.github_url import InvalidGitHubURLError, ParsedGitHubRepo, parse_github_url

_SCAN_URL = "/scan/url"
_EXPRESS_URL = "https://github.com/expressjs/express"
# expressjs/express no longer ships package-lock.json; lodash uses lockfile v1.
_INTEGRATION_REPO_URL = "https://github.com/axios/axios"
_INTERNAL_DETAIL = "Internal error during analysis"


@pytest.fixture
def kill_switch_off(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("ARGUSS_KILL_SWITCH", raising=False)
    monkeypatch.setenv("ARGUSS_KILL_SWITCH_FILE_PATH", str(tmp_path / "kill_switch_absent"))


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


@pytest.fixture
def parsed_express() -> ParsedGitHubRepo:
    return parse_github_url(_EXPRESS_URL)


def _minimal_proposal_report(repo: Path) -> ProposalReport:
    lockfile = repo / "package-lock.json"
    return ProposalReport(
        repo_path=str(repo),
        lockfile_path=str(lockfile),
        entries=(),
        skipped_findings=(),
        summary=ProposalSummary(
            total_findings=0,
            total_candidates=0,
            auto_merge_count=0,
            review_required_count=0,
            decline_count=0,
        ),
    )


def _mock_fetch_inputs(dest: Path) -> RepoInputs:
    dest.mkdir(parents=True, exist_ok=True)
    lockfile = dest / "package-lock.json"
    lockfile.write_text(
        '{"lockfileVersion": 3, "packages": {"": {"name": "scan-url-test", "version": "1.0.0"}}}',
        encoding="utf-8",
    )
    return RepoInputs(work_tree=dest, lockfile_path=lockfile)


async def _async_fetch_inputs(owner: str, repo: str, ref: str, dest: Path) -> RepoInputs:
    return _mock_fetch_inputs(dest)


# --- URL parsing (8) ---


def test_parse_github_url_canonical_form() -> None:
    parsed = parse_github_url("https://github.com/expressjs/express")
    assert parsed.owner == "expressjs"
    assert parsed.name == "express"


def test_parse_github_url_with_dot_git_suffix() -> None:
    parsed = parse_github_url("https://github.com/expressjs/express.git")
    assert parsed.name == "express"
    assert parsed.clone_url == "https://github.com/expressjs/express.git"


def test_parse_github_url_with_tree_path() -> None:
    parsed = parse_github_url("https://github.com/expressjs/express/tree/4.x")
    assert parsed.owner == "expressjs"
    assert parsed.name == "express"


def test_parse_github_url_rejects_non_github_host() -> None:
    with pytest.raises(InvalidGitHubURLError, match="github.com"):
        parse_github_url("https://gitlab.com/someone/some-repo")


def test_parse_github_url_rejects_ssh_url() -> None:
    with pytest.raises(InvalidGitHubURLError, match="SSH"):
        parse_github_url("git@github.com:expressjs/express.git")


def test_parse_github_url_rejects_too_short_path() -> None:
    with pytest.raises(InvalidGitHubURLError, match="owner and repository"):
        parse_github_url("https://github.com/expressjs")


def test_parse_github_url_rejects_path_traversal() -> None:
    with pytest.raises(InvalidGitHubURLError, match="path traversal"):
        parse_github_url("https://github.com/expressjs/express/../../../etc")


def test_parse_github_url_normalizes_clone_url() -> None:
    parsed = parse_github_url("github.com/MyOrg/my_repo")
    assert parsed.clone_url == "https://github.com/MyOrg/my_repo.git"


# --- Git clone wrapper (5) ---


def test_shallow_clone_success(tmp_path: Path) -> None:
    dest = tmp_path / "repo"
    with (
        mock.patch.object(git_clone_mod.shutil, "which", return_value="/usr/bin/git"),
        mock.patch.object(git_clone_mod.subprocess, "run") as run,
    ):
        run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        result = shallow_clone("https://github.com/o/r.git", dest)

    assert result == dest.resolve()
    run.assert_called_once()
    assert run.call_args.kwargs.get("shell") is not True


def test_shallow_clone_timeout_raises(tmp_path: Path) -> None:
    dest = tmp_path / "repo"
    with (
        mock.patch.object(git_clone_mod.shutil, "which", return_value="/usr/bin/git"),
        mock.patch.object(git_clone_mod.subprocess, "run") as run,
    ):
        run.side_effect = subprocess.TimeoutExpired(cmd=["git", "clone"], timeout=60)
        with pytest.raises(GitCloneError, match="timed out") as exc_info:
            shallow_clone("https://github.com/o/r.git", dest)

    assert isinstance(exc_info.value.__cause__, subprocess.TimeoutExpired)


def test_shallow_clone_nonzero_exit_raises(tmp_path: Path) -> None:
    dest = tmp_path / "repo"
    with (
        mock.patch.object(git_clone_mod.shutil, "which", return_value="/usr/bin/git"),
        mock.patch.object(git_clone_mod.subprocess, "run") as run,
    ):
        run.return_value = mock.Mock(returncode=128, stdout="", stderr="fatal: not found")
        with pytest.raises(GitCloneError, match="fatal: not found") as exc_info:
            shallow_clone("https://github.com/o/r.git", dest)

    assert "fatal: not found" in str(exc_info.value)


def test_shallow_clone_git_not_on_path(tmp_path: Path) -> None:
    dest = tmp_path / "repo"
    with (
        mock.patch.object(git_clone_mod.shutil, "which", return_value=None),
        pytest.raises(GitCloneError, match="not found"),
    ):
        shallow_clone("https://github.com/o/r.git", dest)


def test_shallow_clone_args_use_list_form_not_shell(tmp_path: Path) -> None:
    dest = tmp_path / "repo"
    clone_url = "https://github.com/o/r.git"
    with (
        mock.patch.object(git_clone_mod.shutil, "which", return_value="/usr/bin/git"),
        mock.patch.object(git_clone_mod.subprocess, "run") as run,
    ):
        run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        shallow_clone(clone_url, dest)

    args, kwargs = run.call_args
    assert kwargs.get("shell") is not True
    assert args[0][0] == "git"
    assert clone_url in args[0]
    assert str(dest.resolve()) in args[0]


# --- Endpoint (7) ---


def test_scan_url_success_returns_proposal_report(
    client: TestClient,
    parsed_express: ParsedGitHubRepo,
    tmp_path: Path,
) -> None:
    fake_report = _minimal_proposal_report(tmp_path / "express")

    async def fake_fetch(owner: str, repo: str, ref: str, dest: Path) -> RepoInputs:
        return _mock_fetch_inputs(dest)

    with (
        mock.patch.object(routes_mod, "fetch_repo_inputs", side_effect=fake_fetch),
        mock.patch.object(routes_mod, "propose_fixes", return_value=fake_report),
    ):
        response = client.post(_SCAN_URL, json={"url": _EXPRESS_URL})

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert set(data.keys()) == {
        "repo_path",
        "lockfile_path",
        "entries",
        "skipped_findings",
        "summary",
        "executive_summary",
        "project_scores",
    }
    assert data["summary"]["total_candidates"] == 0
    assert parsed_express.name == "express"


def test_scan_url_invalid_url_returns_400(client: TestClient) -> None:
    response = client.post(_SCAN_URL, json={"url": "https://gitlab.com/o/r"})
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "detail" in response.json()
    assert response.json()["detail"]


def test_scan_url_fetch_failure_returns_404(client: TestClient) -> None:
    with mock.patch.object(
        routes_mod,
        "fetch_repo_inputs",
        side_effect=GitHubFetchError("Repository or ref not found", 404),
    ):
        response = client.post(_SCAN_URL, json={"url": _EXPRESS_URL})

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Repository or ref not found"


def test_scan_url_fetch_timeout_returns_504(client: TestClient) -> None:
    with mock.patch.object(
        routes_mod,
        "fetch_repo_inputs",
        side_effect=GitHubFetchError("GitHub API request timed out", 504),
    ):
        response = client.post(_SCAN_URL, json={"url": _EXPRESS_URL})

    assert response.status_code == status.HTTP_504_GATEWAY_TIMEOUT
    assert response.json()["detail"] == "GitHub API request timed out"


def test_scan_url_missing_lockfile_returns_422(client: TestClient) -> None:
    with mock.patch.object(
        routes_mod,
        "fetch_repo_inputs",
        side_effect=GitHubFetchError(
            "Repository does not contain a package-lock.json",
            422,
        ),
    ):
        response = client.post(_SCAN_URL, json={"url": _EXPRESS_URL})

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert response.json()["detail"] == "Repository does not contain a package-lock.json"


def test_scan_url_parser_error_returns_422(client: TestClient) -> None:
    parse_message = "lockfile version 1 is not supported"
    with (
        mock.patch.object(
            routes_mod,
            "fetch_repo_inputs",
            side_effect=lambda owner, repo, ref, dest: _mock_fetch_inputs(dest),
        ),
        mock.patch.object(
            routes_mod,
            "propose_fixes",
            side_effect=ParserError(parse_message),
        ),
    ):
        response = client.post(_SCAN_URL, json={"url": _EXPRESS_URL})

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert response.json()["detail"] == f"Could not parse lockfile: {parse_message}"


@pytest.mark.parametrize(
    ("side_effect",),
    [
        (ZizmorClientError("zizmor failed"),),
        (RuntimeError("unexpected boom"),),
    ],
)
def test_scan_url_internal_error_returns_500(
    client: TestClient,
    side_effect: BaseException,
) -> None:
    with (
        mock.patch.object(
            routes_mod,
            "fetch_repo_inputs",
            side_effect=lambda owner, repo, ref, dest: _mock_fetch_inputs(dest),
        ),
        mock.patch.object(routes_mod, "propose_fixes", side_effect=side_effect),
    ):
        response = client.post(_SCAN_URL, json={"url": _EXPRESS_URL})

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    body = response.json()
    assert body["detail"] == _INTERNAL_DETAIL
    assert "traceback" not in response.text.lower()
    assert "RuntimeError" not in response.text
    assert "ZizmorClientError" not in response.text


def test_scan_url_http_exception_is_not_converted_to_500(client: TestClient) -> None:
    """HTTPException raised inside the handler must pass through unchanged."""
    with mock.patch.object(
        routes_mod,
        "fetch_repo_inputs",
        side_effect=HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="preserved client-facing detail",
        ),
    ):
        response = client.post(_SCAN_URL, json={"url": _EXPRESS_URL})

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "preserved client-facing detail"
    assert response.json()["detail"] != _INTERNAL_DETAIL


def test_scan_url_tempdir_cleaned_up(client: TestClient, tmp_path: Path) -> None:
    recorded: list[Path] = []

    async def fake_fetch(owner: str, repo: str, ref: str, dest: Path) -> RepoInputs:
        recorded.append(dest)
        return _mock_fetch_inputs(dest)

    fake_report = _minimal_proposal_report(tmp_path / "express")

    with (
        mock.patch.object(routes_mod, "fetch_repo_inputs", side_effect=fake_fetch),
        mock.patch.object(routes_mod, "propose_fixes", return_value=fake_report),
    ):
        response = client.post(_SCAN_URL, json={"url": _EXPRESS_URL})

    assert response.status_code == status.HTTP_200_OK
    assert len(recorded) == 1
    clone_dest = recorded[0]
    assert not clone_dest.exists()
    assert not clone_dest.parent.exists()


def test_scan_url_default_ref_head(
    client: TestClient,
    tmp_path: Path,
) -> None:
    captured: list[str] = []

    async def fake_fetch(owner: str, repo: str, ref: str, dest: Path) -> RepoInputs:
        captured.append(ref)
        return _mock_fetch_inputs(dest)

    fake_report = _minimal_proposal_report(tmp_path / "express")
    with (
        mock.patch.object(routes_mod, "fetch_repo_inputs", side_effect=fake_fetch),
        mock.patch.object(routes_mod, "propose_fixes", return_value=fake_report),
    ):
        response = client.post(_SCAN_URL, json={"url": _EXPRESS_URL})

    assert response.status_code == status.HTTP_200_OK
    assert captured == ["HEAD"]


def test_scan_url_explicit_ref_passed_to_fetcher(
    client: TestClient,
    tmp_path: Path,
) -> None:
    captured: list[str] = []

    async def fake_fetch(owner: str, repo: str, ref: str, dest: Path) -> RepoInputs:
        captured.append(ref)
        return _mock_fetch_inputs(dest)

    fake_report = _minimal_proposal_report(tmp_path / "express")
    with (
        mock.patch.object(routes_mod, "fetch_repo_inputs", side_effect=fake_fetch),
        mock.patch.object(routes_mod, "propose_fixes", return_value=fake_report),
    ):
        response = client.post(
            _SCAN_URL,
            json={"url": _EXPRESS_URL, "ref": "4.17.0"},
        )

    assert response.status_code == status.HTTP_200_OK
    assert captured == ["4.17.0"]


def test_scan_url_rate_limit_returns_429(client: TestClient) -> None:
    with mock.patch.object(
        routes_mod,
        "fetch_repo_inputs",
        side_effect=GitHubFetchError("GitHub API rate limit exceeded", 429),
    ):
        response = client.post(_SCAN_URL, json={"url": _EXPRESS_URL})

    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert response.json()["detail"] == "GitHub API rate limit exceeded"


# --- Integration ---


@pytest.mark.integration
def test_scan_url_integration_against_axios(
    client: TestClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kill_switch_off: None,
) -> None:
    """End-to-end: real GitHub API fetch, real OSV, real propose_fixes.

    Uses axios/axios (lockfile v3 at repo root). expressjs/express no longer
    ships package-lock.json; the capstone express *fixture* is a separate npm project.
    """
    db = tmp_path / "scan_url_integration.db"
    monkeypatch.setattr(live_settings, "db_path", db)
    monkeypatch.setattr(Settings, "db_path", db)

    response = client.post(_SCAN_URL, json={"url": _INTEGRATION_REPO_URL})

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert set(data.keys()) == {
        "repo_path",
        "lockfile_path",
        "entries",
        "skipped_findings",
        "summary",
        "executive_summary",
        "project_scores",
    }
    assert isinstance(data["entries"], list)
    assert len(data["entries"]) >= 1
    summary = data["summary"]
    assert summary["total_candidates"] == len(data["entries"])
    assert summary["total_findings"] >= 1
    assert summary["auto_merge_count"] + summary["review_required_count"] + summary[
        "decline_count"
    ] == len(data["entries"])

    entry = data["entries"][0]
    assert set(entry.keys()) == {"finding", "candidate", "verdict"}
    assert entry["finding"]["advisory_id"]
    assert entry["candidate"]["candidate_id"]
    assert entry["verdict"]["candidate_id"] == entry["candidate"]["candidate_id"]


def test_scan_response_includes_executive_summary_when_available(
    client: TestClient,
    kill_switch_off: None,
    tmp_path: Path,
) -> None:
    fake_report = _minimal_proposal_report(tmp_path / "express")

    with (
        mock.patch.object(
            routes_mod,
            "fetch_repo_inputs",
            side_effect=_async_fetch_inputs,
        ),
        mock.patch.object(routes_mod, "propose_fixes", return_value=fake_report),
        mock.patch(
            "arguss.explanations.executive_summary.generate_executive_summary",
            return_value="Scan looks manageable with a few review items.",
        ),
    ):
        response = client.post(
            _SCAN_URL,
            json={"url": _EXPRESS_URL, "ref": "main"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["executive_summary"] == "Scan looks manageable with a few review items."


def test_scan_response_omits_executive_summary_when_claude_unavailable(
    client: TestClient,
    kill_switch_off: None,
    tmp_path: Path,
) -> None:
    fake_report = _minimal_proposal_report(tmp_path / "express")

    with (
        mock.patch.object(
            routes_mod,
            "fetch_repo_inputs",
            side_effect=_async_fetch_inputs,
        ),
        mock.patch.object(routes_mod, "propose_fixes", return_value=fake_report),
        mock.patch(
            "arguss.explanations.executive_summary.generate_executive_summary",
            return_value=None,
        ),
    ):
        response = client.post(
            _SCAN_URL,
            json={"url": _EXPRESS_URL, "ref": "main"},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["executive_summary"] is None
    assert "summary" in data
    assert "entries" in data
