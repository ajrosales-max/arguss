"""Tests for git-ref validation at every ref entry point (finding #2).

A user-supplied ref reaches two sinks: the GitHub API path
``.../git/trees/{ref}`` (path traversal) and ``git clone --branch <ref>``
(option injection). Every route that accepts a ref must reject unsafe values
before either sink is reached.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
import arguss.web.routes as routes_mod
import arguss.web.url_scan as url_scan_mod
from arguss.api import app as api_app
from arguss.web.github_url import InvalidGitRefError, validate_git_ref
from arguss.web.url_scan import run_scan_from_url

_EXPRESS_URL = "https://github.com/expressjs/express"
_TRAVERSAL_REF = "../../../../user"

_GOOD_REFS = [
    "HEAD",
    "main",
    "feature/x",
    "v1.0.0",
    "release-1.0",
    "a3f5c2e9b1d4a6c8e0f2b4d6a8c0e2f4b6d8a0c2",
    "users/alice/fix_thing",
]

_BAD_REFS = [
    _TRAVERSAL_REF,
    "..",
    "a..b",
    "-foo",
    "--upload-pack=/tmp/x",
    "/main",
    "main/",
    "a//b",
    "a b",
    "a\tb",
    "a\nb",
    "a\x01b",
    "a~b",
    "a^b",
    "a:b",
    "a?b",
    "a*b",
    "a[b",
    "a@{b}",
    "a\\b",
    "main.lock",
]


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


# --- unit: validate_git_ref ---


@pytest.mark.parametrize("ref", _GOOD_REFS)
def test_validate_git_ref_accepts_legitimate_refs(ref: str) -> None:
    assert validate_git_ref(ref) == ref


def test_validate_git_ref_empty_means_head() -> None:
    assert validate_git_ref("") == "HEAD"


@pytest.mark.parametrize("ref", _BAD_REFS)
def test_validate_git_ref_rejects_unsafe_refs(ref: str) -> None:
    with pytest.raises(InvalidGitRefError):
        validate_git_ref(ref)


def test_validate_git_ref_rejects_overlong_ref() -> None:
    with pytest.raises(InvalidGitRefError):
        validate_git_ref("a" * 256)


# --- POST /scan/url (JSON, Mode A) ---


def test_scan_url_rejects_traversal_ref_before_fetch(client: TestClient) -> None:
    fetch = mock.AsyncMock()
    with mock.patch.object(routes_mod, "fetch_repo_inputs", fetch):
        response = client.post(
            "/scan/url",
            json={"url": _EXPRESS_URL, "ref": _TRAVERSAL_REF},
        )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "detail" in response.json()
    fetch.assert_not_called()


@pytest.mark.parametrize("ref", ["HEAD", "main", "feature/x", "v1.0.0"])
def test_scan_url_accepts_legitimate_refs(client: TestClient, ref: str) -> None:
    fetch = mock.AsyncMock(side_effect=RuntimeError("stop after validation"))
    with mock.patch.object(routes_mod, "fetch_repo_inputs", fetch):
        response = client.post("/scan/url", json={"url": _EXPRESS_URL, "ref": ref})

    # The ref passed validation and reached the (stubbed) fetch stage.
    assert response.status_code != status.HTTP_400_BAD_REQUEST
    fetch.assert_called_once()


# --- POST /scan/with-action and /start (JSON, Mode C clone path) ---


@pytest.mark.parametrize("ref", [_TRAVERSAL_REF, "-foo", "a\x01b"])
def test_scan_with_action_rejects_unsafe_ref_before_clone(
    client: TestClient,
    ref: str,
) -> None:
    execute = mock.AsyncMock()
    with mock.patch.object(routes_mod, "execute_scan_with_action", execute):
        response = client.post(
            "/scan/with-action",
            json={"url": _EXPRESS_URL, "installation_id": 12345, "ref": ref},
        )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    execute.assert_not_called()


@pytest.mark.parametrize("ref", [_TRAVERSAL_REF, "-foo", "a\x01b"])
def test_scan_with_action_start_rejects_unsafe_ref_before_clone(
    client: TestClient,
    ref: str,
) -> None:
    run = mock.AsyncMock()
    with mock.patch.object(routes_mod, "run_scan_background", run):
        response = client.post(
            "/scan/with-action/start",
            json={"url": _EXPRESS_URL, "installation_id": 12345, "ref": ref},
        )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    run.assert_not_called()


# --- POST /dashboard/scan (browser, Mode A) ---


def test_dashboard_scan_rejects_traversal_ref_with_error_card(
    client: TestClient,
) -> None:
    fetch = mock.AsyncMock()
    with mock.patch.object(dashboard_mod, "fetch_repo_inputs", fetch):
        response = client.post(
            "/dashboard/scan",
            data={"url": _EXPRESS_URL, "ref": _TRAVERSAL_REF},
        )

    assert "error-card" in response.text
    fetch.assert_not_called()


# --- POST /dashboard/scan-with-action and /start (browser, Mode C clone path) ---


@pytest.mark.parametrize("ref", [_TRAVERSAL_REF, "-foo"])
def test_dashboard_scan_with_action_start_rejects_unsafe_ref(
    client: TestClient,
    ref: str,
) -> None:
    run = mock.AsyncMock()
    with mock.patch.object(dashboard_mod, "run_scan_background", run):
        response = client.post(
            "/dashboard/scan-with-action/start",
            data={"url": _EXPRESS_URL, "ref": ref},
        )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "error" in response.json()
    run.assert_not_called()


@pytest.mark.parametrize("ref", [_TRAVERSAL_REF, "-foo"])
def test_dashboard_scan_with_action_rejects_unsafe_ref(
    client: TestClient,
    ref: str,
) -> None:
    execute = mock.AsyncMock()
    with mock.patch.object(dashboard_mod, "execute_scan_with_action", execute):
        response = client.post(
            "/dashboard/scan-with-action",
            data={"url": _EXPRESS_URL, "ref": ref},
        )

    assert "error-card" in response.text
    execute.assert_not_called()


# --- run_scan_from_url (assessment cache-miss rescan path) ---


def test_run_scan_from_url_rejects_traversal_ref_before_fetch(
    tmp_path: Path,
) -> None:
    fetch = mock.AsyncMock()
    with (
        mock.patch.object(url_scan_mod, "fetch_repo_inputs", fetch),
        pytest.raises(InvalidGitRefError),
    ):
        asyncio.run(run_scan_from_url(_EXPRESS_URL, ref=_TRAVERSAL_REF))

    fetch.assert_not_called()
