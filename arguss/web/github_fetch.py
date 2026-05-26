"""GitHub Contents API client for fetching repo inputs without cloning."""

from __future__ import annotations

import asyncio
import base64
import binascii
import fnmatch
import os
from dataclasses import dataclass
from pathlib import Path

import httpx

_GITHUB_API = "https://api.github.com"
_LOCKFILE = "package-lock.json"
_PACKAGE_JSON = "package.json"
_WORKFLOWS_PREFIX = ".github/workflows/"


class GitHubFetchError(Exception):
    """Base for fetch errors. Carries a status_code for HTTP translation."""

    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class RepoInputs:
    """Files assembled into a temp working tree, ready for propose_fixes."""

    work_tree: Path
    lockfile_path: Path


def _auth_headers() -> dict[str, str]:
    token = os.environ.get("ARGUSS_GITHUB_TOKEN")
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def _status_code_from_response(response: httpx.Response) -> int:
    code = response.status_code
    if code == 404:
        return 404
    if code == 401:
        return 401
    if code == 403 and response.headers.get("X-RateLimit-Remaining") == "0":
        return 429
    if 400 <= code < 600:
        return 500
    return 500


def _raise_for_response(response: httpx.Response, context: str) -> None:
    if response.is_success:
        return
    status_code = _status_code_from_response(response)
    message = context
    if status_code == 429:
        message = "GitHub API rate limit exceeded"
    elif status_code == 404:
        message = "Repository or ref not found"
    raise GitHubFetchError(message, status_code)


def _is_unsafe_tree_path(path: str) -> bool:
    return path.startswith("/") or ".." in path


def _is_test_file_basename(name: str) -> bool:
    return fnmatch.fnmatch(name, "*.test.*") or fnmatch.fnmatch(name, "*.spec.*")


def _safe_dest_path(dest: Path, relative_path: str) -> Path:
    target = (dest / relative_path).resolve()
    dest_resolved = dest.resolve()
    if dest_resolved not in target.parents and target != dest_resolved:
        raise GitHubFetchError(f"Unsafe path in repository tree: {relative_path!r}", 500)
    return target


async def _fetch_tree(
    client: httpx.AsyncClient,
    owner: str,
    repo: str,
    ref: str,
) -> list[str]:
    response = await client.get(f"/repos/{owner}/{repo}/git/trees/{ref}", params={"recursive": "1"})
    _raise_for_response(response, "Repository or ref not found")
    payload = response.json()
    paths: list[str] = []
    for entry in payload.get("tree", []):
        if entry.get("type") != "blob":
            continue
        path = entry.get("path")
        if not isinstance(path, str):
            continue
        if _is_unsafe_tree_path(path):
            raise GitHubFetchError(f"Unsafe path in repository tree: {path!r}", 500)
        paths.append(path)
    return paths


async def _fetch_file_bytes(
    client: httpx.AsyncClient,
    owner: str,
    repo: str,
    ref: str,
    path: str,
) -> bytes:
    response = await client.get(
        f"/repos/{owner}/{repo}/contents/{path}",
        params={"ref": ref},
    )
    _raise_for_response(response, f"Failed to fetch {path}")
    payload = response.json()
    encoding = payload.get("encoding")
    content = payload.get("content")
    if encoding != "base64" or not isinstance(content, str):
        raise GitHubFetchError(f"Unexpected content encoding for {path}", 500)
    try:
        return base64.b64decode(content.replace("\n", ""), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise GitHubFetchError(f"Failed to decode {path}", 500) from exc


def _workflow_paths(paths: list[str]) -> list[str]:
    result: list[str] = []
    for path in paths:
        if not path.startswith(_WORKFLOWS_PREFIX):
            continue
        name = path[len(_WORKFLOWS_PREFIX) :]
        if name.endswith((".yml", ".yaml")):
            result.append(path)
    return result


def _test_file_paths(paths: list[str]) -> list[str]:
    return [path for path in paths if _is_test_file_basename(Path(path).name)]


async def fetch_repo_inputs(
    owner: str,
    repo: str,
    ref: str,
    dest: Path,
    timeout: float = 30.0,
) -> RepoInputs:
    """Fetch the files propose_fixes needs into `dest`.

    Steps:
    - GET /repos/{owner}/{repo}/git/trees/{ref}?recursive=1 to list paths
    - For each needed file, GET /repos/{owner}/{repo}/contents/{path}?ref={ref}
      and decode the base64 `content` field
    - Required: package-lock.json (else raise GitHubFetchError(422))
    - Optional: package.json, .github/workflows/*.yml, .github/workflows/*.yaml
    - Test files: create zero-byte stubs at discovered *.test.* / *.spec.* paths

    Raises GitHubFetchError on any non-success outcome.
    """
    dest.mkdir(parents=True, exist_ok=True)
    headers = {
        "Accept": "application/vnd.github+json",
        **_auth_headers(),
    }

    try:
        async with httpx.AsyncClient(
            base_url=_GITHUB_API,
            timeout=timeout,
            headers=headers,
        ) as client:
            paths = await _fetch_tree(client, owner, repo, ref)
            path_set = set(paths)

            if _LOCKFILE not in path_set:
                raise GitHubFetchError(
                    "Repository does not contain a package-lock.json",
                    422,
                )

            files_to_fetch = [_LOCKFILE]
            if _PACKAGE_JSON in path_set:
                files_to_fetch.append(_PACKAGE_JSON)
            files_to_fetch.extend(_workflow_paths(paths))

            async def fetch_one(path: str) -> tuple[str, bytes]:
                data = await _fetch_file_bytes(client, owner, repo, ref, path)
                return path, data

            fetched = await asyncio.gather(*(fetch_one(path) for path in files_to_fetch))

            for path, data in fetched:
                target = _safe_dest_path(dest, path)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)

            for test_path in _test_file_paths(paths):
                target = _safe_dest_path(dest, test_path)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"")

    except httpx.TimeoutException as exc:
        raise GitHubFetchError("GitHub API request timed out", 504) from exc
    except httpx.RequestError as exc:
        raise GitHubFetchError("GitHub API network error", 504) from exc

    lockfile_path = dest / _LOCKFILE
    return RepoInputs(work_tree=dest, lockfile_path=lockfile_path)
