"""Tests for HTTP Basic Auth gated by ARGUSS_REQUIRE_AUTH."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.api as api_mod
import arguss.settings as settings_mod
import arguss.web.auth as auth_mod
import arguss.web.routes as routes_mod
from arguss.api import create_app
from arguss.engine.propose import ProposalReport, ProposalSummary
from arguss.settings import Settings
from arguss.web.github_fetch import RepoInputs

_EXPRESS_URL = "https://github.com/expressjs/express"
_SCAN_URL = "/scan/url"
_FIXTURES = Path(__file__).parent / "fixtures" / "lockfiles"


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


async def _mock_fetch_inputs(owner: str, repo: str, ref: str, dest: Path) -> RepoInputs:
    dest.mkdir(parents=True, exist_ok=True)
    lockfile = dest / "package-lock.json"
    lockfile.write_bytes((_FIXTURES / "minimal.json").read_bytes())
    return RepoInputs(work_tree=dest, lockfile_path=lockfile)


@pytest.fixture
def auth_client(monkeypatch: pytest.MonkeyPatch) -> Callable[..., TestClient]:
    """Build a fresh app after patching require_auth / credential settings."""

    def _factory(
        *,
        require_auth: bool = False,
        demo_password: str | None = None,
        demo_username: str = "demo",
    ) -> TestClient:
        if require_auth and not demo_password:
            demo_password = "testpass"
        monkeypatch.setattr(Settings, "require_auth", require_auth)
        monkeypatch.setattr(Settings, "demo_username", demo_username)
        monkeypatch.setattr(Settings, "demo_password", demo_password)
        patched = Settings()
        monkeypatch.setattr(settings_mod, "settings", patched)
        monkeypatch.setattr(auth_mod, "settings", patched)
        monkeypatch.setattr(api_mod, "settings", patched)
        return TestClient(create_app())

    return _factory


def test_routes_open_when_require_auth_false(
    auth_client: Callable[..., TestClient],
    tmp_path: Path,
) -> None:
    client = auth_client(require_auth=False, demo_password=None)
    fake_report = _minimal_proposal_report(tmp_path / "express")

    assert client.get("/").status_code == status.HTTP_200_OK
    assert client.get("/health").status_code == status.HTTP_200_OK

    with (
        mock.patch.object(routes_mod, "fetch_repo_inputs", side_effect=_mock_fetch_inputs),
        mock.patch.object(routes_mod, "propose_fixes", return_value=fake_report),
    ):
        response = client.post(_SCAN_URL, json={"url": _EXPRESS_URL})

    assert response.status_code == status.HTTP_200_OK


def test_routes_protected_when_require_auth_true(
    auth_client: Callable[..., TestClient],
) -> None:
    client = auth_client(require_auth=True, demo_password="testpass")
    response = client.get("/")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.headers.get("www-authenticate") == 'Basic realm="Arguss"'


def test_routes_open_with_correct_credentials(auth_client: Callable[..., TestClient]) -> None:
    client = auth_client(require_auth=True, demo_password="testpass")
    response = client.get("/", auth=("demo", "testpass"))

    assert response.status_code == status.HTTP_200_OK
    assert "text/html" in response.headers["content-type"]


def test_routes_401_with_wrong_password(auth_client: Callable[..., TestClient]) -> None:
    client = auth_client(require_auth=True, demo_password="testpass")
    response = client.get("/", auth=("demo", "wrong"))

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_routes_401_with_wrong_username(auth_client: Callable[..., TestClient]) -> None:
    client = auth_client(require_auth=True, demo_password="testpass")
    response = client.get("/", auth=("notdemo", "testpass"))

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_health_open_even_when_auth_enabled(auth_client: Callable[..., TestClient]) -> None:
    client = auth_client(require_auth=True, demo_password="testpass")
    response = client.get("/health")

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["status"] == "ok"


def test_docs_disabled_when_auth_enabled(auth_client: Callable[..., TestClient]) -> None:
    client = auth_client(require_auth=True, demo_password="testpass")
    assert client.get("/docs").status_code == status.HTTP_404_NOT_FOUND
    assert client.get("/redoc").status_code == status.HTTP_404_NOT_FOUND
    assert client.get("/openapi.json").status_code == status.HTTP_404_NOT_FOUND


def test_docs_enabled_when_auth_disabled(auth_client: Callable[..., TestClient]) -> None:
    client = auth_client(require_auth=False, demo_password=None)
    assert client.get("/docs").status_code == status.HTTP_200_OK
