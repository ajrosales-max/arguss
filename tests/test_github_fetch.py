"""Unit tests for GitHub Contents API fetcher."""

from __future__ import annotations

import base64
from pathlib import Path

import httpx
import pytest
import respx

from arguss.web.github_fetch import GitHubFetchError, RepoInputs, fetch_repo_inputs

_API = "https://api.github.com"
_OWNER = "acme"
_REPO = "widget"
_REF = "main"


def _tree_response(paths: list[str]) -> dict:
    return {
        "sha": "abc",
        "tree": [{"path": p, "type": "blob", "mode": "100644", "sha": "x"} for p in paths],
        "truncated": False,
    }


def _content_response(data: bytes) -> dict:
    return {
        "name": "file",
        "encoding": "base64",
        "content": base64.b64encode(data).decode("ascii"),
    }


def _register_tree(respx_mock: respx.MockRouter, paths: list[str], ref: str = _REF) -> None:
    respx_mock.get(
        f"{_API}/repos/{_OWNER}/{_REPO}/git/trees/{ref}",
        params={"recursive": "1"},
    ).respond(json=_tree_response(paths))


def _register_content(
    respx_mock: respx.MockRouter,
    path: str,
    data: bytes,
    ref: str = _REF,
) -> None:
    respx_mock.get(
        f"{_API}/repos/{_OWNER}/{_REPO}/contents/{path}",
        params={"ref": ref},
    ).respond(json=_content_response(data))


def _large_content_response(*, sha: str = "abc123", size: int = 1_500_000) -> dict:
    return {
        "name": "file",
        "encoding": "none",
        "content": "",
        "sha": sha,
        "size": size,
    }


def _blob_response(sha: str, data: bytes) -> dict:
    return {
        "sha": sha,
        "encoding": "base64",
        "content": base64.b64encode(data).decode("ascii"),
    }


def _register_large_content_with_blob(
    respx_mock: respx.MockRouter,
    path: str,
    blob_data: bytes,
    *,
    sha: str = "abc123",
    ref: str = _REF,
) -> None:
    respx_mock.get(
        f"{_API}/repos/{_OWNER}/{_REPO}/contents/{path}",
        params={"ref": ref},
    ).respond(json=_large_content_response(sha=sha))
    respx_mock.get(f"{_API}/repos/{_OWNER}/{_REPO}/git/blobs/{sha}").respond(
        json=_blob_response(sha, blob_data),
    )


@pytest.mark.asyncio
@respx.mock
async def test_fetch_repo_inputs_full_assembly(tmp_path: Path) -> None:
    paths = [
        "package-lock.json",
        "package.json",
        ".github/workflows/ci.yml",
        "src/foo.test.ts",
        "lib/bar.spec.js",
    ]
    _register_tree(respx, paths)
    lock_bytes = b'{"lockfileVersion": 3}'
    pkg_bytes = b'{"name": "widget"}'
    wf_bytes = b"name: CI\n"
    _register_content(respx, "package-lock.json", lock_bytes)
    _register_content(respx, "package.json", pkg_bytes)
    _register_content(respx, ".github/workflows/ci.yml", wf_bytes)

    dest = tmp_path / "work"
    result = await fetch_repo_inputs(_OWNER, _REPO, _REF, dest)

    assert result == RepoInputs(work_tree=dest, lockfile_path=dest / "package-lock.json")
    assert (dest / "package-lock.json").read_bytes() == lock_bytes
    assert (dest / "package.json").read_bytes() == pkg_bytes
    assert (dest / ".github/workflows/ci.yml").read_bytes() == wf_bytes
    assert (dest / "src/foo.test.ts").read_bytes() == b""
    assert (dest / "lib/bar.spec.js").read_bytes() == b""


@pytest.mark.asyncio
@respx.mock
async def test_fetch_repo_inputs_lockfile_only(tmp_path: Path) -> None:
    _register_tree(respx, ["package-lock.json"])
    lock_bytes = b'{"lockfileVersion": 3}'
    _register_content(respx, "package-lock.json", lock_bytes)

    dest = tmp_path / "work"
    result = await fetch_repo_inputs(_OWNER, _REPO, _REF, dest)

    assert result.lockfile_path.is_file()
    assert not (dest / "package.json").exists()
    assert not (dest / ".github").exists()


@pytest.mark.asyncio
@respx.mock
async def test_fetch_tree_404(tmp_path: Path) -> None:
    respx.get(f"{_API}/repos/{_OWNER}/{_REPO}/git/trees/{_REF}").respond(404)

    with pytest.raises(GitHubFetchError) as exc_info:
        await fetch_repo_inputs(_OWNER, _REPO, _REF, tmp_path / "work")

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
@respx.mock
async def test_fetch_missing_lockfile_in_tree(tmp_path: Path) -> None:
    _register_tree(respx, ["package.json", "README.md"])

    with pytest.raises(GitHubFetchError) as exc_info:
        await fetch_repo_inputs(_OWNER, _REPO, _REF, tmp_path / "work")

    assert exc_info.value.status_code == 422
    assert "package-lock.json" in str(exc_info.value)


@pytest.mark.asyncio
@respx.mock
async def test_fetch_rate_limit_429(tmp_path: Path) -> None:
    respx.get(f"{_API}/repos/{_OWNER}/{_REPO}/git/trees/{_REF}").respond(
        403,
        headers={"X-RateLimit-Remaining": "0"},
    )

    with pytest.raises(GitHubFetchError) as exc_info:
        await fetch_repo_inputs(_OWNER, _REPO, _REF, tmp_path / "work")

    assert exc_info.value.status_code == 429


@pytest.mark.asyncio
async def test_fetch_timeout_504(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def raise_timeout(self, *_args, **_kwargs):
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr(httpx.AsyncClient, "get", raise_timeout)

    with pytest.raises(GitHubFetchError) as exc_info:
        await fetch_repo_inputs(_OWNER, _REPO, _REF, tmp_path / "work")

    assert exc_info.value.status_code == 504


@pytest.mark.asyncio
@respx.mock
async def test_fetch_includes_bearer_when_token_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ARGUSS_GITHUB_TOKEN", "ghp_test_token")
    _register_tree(respx, ["package-lock.json"])
    _register_content(respx, "package-lock.json", b"{}")

    await fetch_repo_inputs(_OWNER, _REPO, _REF, tmp_path / "work")

    request = respx.calls[0].request
    assert request.headers["Authorization"] == "Bearer ghp_test_token"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_no_auth_header_without_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ARGUSS_GITHUB_TOKEN", raising=False)
    _register_tree(respx, ["package-lock.json"])
    _register_content(respx, "package-lock.json", b"{}")

    await fetch_repo_inputs(_OWNER, _REPO, _REF, tmp_path / "work")

    request = respx.calls[0].request
    assert "Authorization" not in request.headers


@pytest.mark.asyncio
@respx.mock
async def test_test_file_contents_not_fetched(tmp_path: Path) -> None:
    paths = ["package-lock.json", "tests/app.test.js"]
    _register_tree(respx, paths)
    _register_content(respx, "package-lock.json", b"{}")

    await fetch_repo_inputs(_OWNER, _REPO, _REF, tmp_path / "work")

    content_calls = [c.request.url.path for c in respx.calls if "/contents/" in c.request.url.path]
    assert content_calls == [f"/repos/{_OWNER}/{_REPO}/contents/package-lock.json"]
    assert (tmp_path / "work/tests/app.test.js").exists()
    assert (tmp_path / "work/tests/app.test.js").read_bytes() == b""


@pytest.mark.asyncio
@respx.mock
async def test_unsafe_tree_path_rejected(tmp_path: Path) -> None:
    respx.get(f"{_API}/repos/{_OWNER}/{_REPO}/git/trees/{_REF}").respond(
        json=_tree_response(["package-lock.json", "../etc/passwd"]),
    )

    with pytest.raises(GitHubFetchError) as exc_info:
        await fetch_repo_inputs(_OWNER, _REPO, _REF, tmp_path / "work")

    assert exc_info.value.status_code == 500
    assert "Unsafe path" in str(exc_info.value)


@pytest.mark.asyncio
@respx.mock
async def test_fetch_large_lockfile_via_blob_api(tmp_path: Path) -> None:
    lock_bytes = b'{"name":"test","lockfileVersion":3,"packages":{}}'
    _register_tree(respx, ["package-lock.json"])
    _register_large_content_with_blob(respx, "package-lock.json", lock_bytes)

    dest = tmp_path / "work"
    result = await fetch_repo_inputs(_OWNER, _REPO, _REF, dest)

    assert result.lockfile_path.is_file()
    assert (dest / "package-lock.json").read_bytes() == lock_bytes
    blob_calls = [c for c in respx.calls if "/git/blobs/" in c.request.url.path]
    assert len(blob_calls) == 1


@pytest.mark.asyncio
@respx.mock
async def test_fetch_large_workflow_via_blob_api(tmp_path: Path) -> None:
    wf_path = ".github/workflows/ci.yml"
    wf_bytes = b"name: CI\non: push\n"
    lock_bytes = b'{"lockfileVersion": 3}'
    _register_tree(respx, ["package-lock.json", wf_path])
    _register_content(respx, "package-lock.json", lock_bytes)
    _register_large_content_with_blob(respx, wf_path, wf_bytes, sha="wfsha1")

    dest = tmp_path / "work"
    await fetch_repo_inputs(_OWNER, _REPO, _REF, dest)

    assert (dest / wf_path).read_bytes() == wf_bytes


@pytest.mark.asyncio
@respx.mock
async def test_large_content_none_without_sha(tmp_path: Path) -> None:
    _register_tree(respx, ["package-lock.json"])
    respx.get(
        f"{_API}/repos/{_OWNER}/{_REPO}/contents/package-lock.json",
        params={"ref": _REF},
    ).respond(
        json={
            "encoding": "none",
            "content": "",
            "size": 1_500_000,
        },
    )

    with pytest.raises(GitHubFetchError) as exc_info:
        await fetch_repo_inputs(_OWNER, _REPO, _REF, tmp_path / "work")

    assert exc_info.value.status_code == 500
    assert "No sha" in str(exc_info.value)


@pytest.mark.asyncio
@respx.mock
async def test_blob_api_404(tmp_path: Path) -> None:
    sha = "abc123"
    _register_tree(respx, ["package-lock.json"])
    respx.get(
        f"{_API}/repos/{_OWNER}/{_REPO}/contents/package-lock.json",
        params={"ref": _REF},
    ).respond(json=_large_content_response(sha=sha))
    respx.get(f"{_API}/repos/{_OWNER}/{_REPO}/git/blobs/{sha}").respond(404)

    with pytest.raises(GitHubFetchError) as exc_info:
        await fetch_repo_inputs(_OWNER, _REPO, _REF, tmp_path / "work")

    assert exc_info.value.status_code == 404
    assert "Blob not found" in str(exc_info.value)


@pytest.mark.asyncio
@respx.mock
async def test_blob_api_rate_limit_429(tmp_path: Path) -> None:
    sha = "abc123"
    _register_tree(respx, ["package-lock.json"])
    respx.get(
        f"{_API}/repos/{_OWNER}/{_REPO}/contents/package-lock.json",
        params={"ref": _REF},
    ).respond(json=_large_content_response(sha=sha))
    respx.get(f"{_API}/repos/{_OWNER}/{_REPO}/git/blobs/{sha}").respond(
        403,
        headers={"X-RateLimit-Remaining": "0"},
    )

    with pytest.raises(GitHubFetchError) as exc_info:
        await fetch_repo_inputs(_OWNER, _REPO, _REF, tmp_path / "work")

    assert exc_info.value.status_code == 429


@pytest.mark.asyncio
@respx.mock
async def test_blob_api_timeout_504(tmp_path: Path) -> None:
    sha = "abc123"
    _register_tree(respx, ["package-lock.json"])
    respx.get(
        f"{_API}/repos/{_OWNER}/{_REPO}/contents/package-lock.json",
        params={"ref": _REF},
    ).respond(json=_large_content_response(sha=sha))

    def raise_timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    respx.get(f"{_API}/repos/{_OWNER}/{_REPO}/git/blobs/{sha}").mock(side_effect=raise_timeout)

    with pytest.raises(GitHubFetchError) as exc_info:
        await fetch_repo_inputs(_OWNER, _REPO, _REF, tmp_path / "work")

    assert exc_info.value.status_code == 504
    assert "Timeout fetching blob" in str(exc_info.value)


@pytest.mark.asyncio
@respx.mock
async def test_blob_api_non_base64_encoding(tmp_path: Path) -> None:
    sha = "abc123"
    _register_tree(respx, ["package-lock.json"])
    respx.get(
        f"{_API}/repos/{_OWNER}/{_REPO}/contents/package-lock.json",
        params={"ref": _REF},
    ).respond(json=_large_content_response(sha=sha))
    respx.get(f"{_API}/repos/{_OWNER}/{_REPO}/git/blobs/{sha}").respond(
        json={"encoding": "utf-8", "content": "not-base64", "sha": sha},
    )

    with pytest.raises(GitHubFetchError) as exc_info:
        await fetch_repo_inputs(_OWNER, _REPO, _REF, tmp_path / "work")

    assert exc_info.value.status_code == 500
    assert "Could not decode blob content" in str(exc_info.value)
