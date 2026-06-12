"""Shallow clone a GitHub repo for analysis."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path

_GIT_CLONE_TIMEOUT_SECONDS = 60
_LOG = logging.getLogger(__name__)
_COMMIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


class GitCloneError(Exception):
    """Shallow clone failed (network, repo doesn't exist, permission denied, etc)."""

    KIND_GIT_EXECUTABLE = "git_executable"
    KIND_TIMEOUT = "timeout"
    KIND_CLONE_FAILED = "clone_failed"
    KIND_REF_NOT_FOUND = "ref_not_found"

    def __init__(
        self,
        message: str,
        *,
        kind: str = KIND_CLONE_FAILED,
        ref: str | None = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.ref = ref


def _effective_ref(ref: str | None) -> str | None:
    if ref is None:
        return None
    stripped = ref.strip()
    if not stripped or stripped.upper() == "HEAD":
        return None
    return stripped


def _is_commit_sha_ref(ref: str) -> bool:
    return _COMMIT_SHA_RE.fullmatch(ref) is not None


def _stderr_indicates_ref_not_found(stderr: str) -> bool:
    lowered = stderr.lower()
    return (
        "couldn't find remote ref" in lowered
        or ("remote branch" in lowered and "not found" in lowered)
        or "not found in upstream" in lowered
        or "invalid object name" in lowered
        or ("is not a commit" in lowered and "cannot be created" in lowered)
    )


def _clone_error_kind(stderr: str, requested_ref: str | None) -> str:
    if requested_ref is not None and _stderr_indicates_ref_not_found(stderr):
        return GitCloneError.KIND_REF_NOT_FOUND
    return GitCloneError.KIND_CLONE_FAILED


def _run_git(
    cmd: list[str],
    *,
    operation: str,
    requested_ref: str | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_GIT_CLONE_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitCloneError(
            "git executable not found on PATH",
            kind=GitCloneError.KIND_GIT_EXECUTABLE,
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise GitCloneError(
            f"git {operation} timed out after {_GIT_CLONE_TIMEOUT_SECONDS} seconds",
            kind=GitCloneError.KIND_TIMEOUT,
        ) from exc

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        message = f"git {operation} failed with exit code {completed.returncode}"
        if stderr:
            message = f"{message}: {stderr}"
        kind = _clone_error_kind(stderr, requested_ref)
        raise GitCloneError(
            message,
            kind=kind,
            ref=requested_ref if kind == GitCloneError.KIND_REF_NOT_FOUND else None,
        )
    return completed


def _clone_default_branch(clone_url: str, dest: Path) -> None:
    cmd = [
        "git",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        clone_url,
        str(dest),
    ]
    _run_git(cmd, operation="clone")


def _clone_branch_or_tag(clone_url: str, dest: Path, ref: str) -> None:
    cmd = [
        "git",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        "--branch",
        ref,
        clone_url,
        str(dest),
    ]
    _run_git(cmd, operation="clone", requested_ref=ref)


def _clone_commit_sha(clone_url: str, dest: Path, sha: str) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    _run_git(["git", "init", str(dest)], operation="init")
    _run_git(
        ["git", "-C", str(dest), "remote", "add", "origin", clone_url],
        operation="remote add",
    )
    _run_git(
        ["git", "-C", str(dest), "fetch", "--depth", "1", "origin", sha],
        operation="fetch",
        requested_ref=sha,
    )
    _run_git(
        ["git", "-C", str(dest), "checkout", "FETCH_HEAD"],
        operation="checkout",
        requested_ref=sha,
    )


def shallow_clone(clone_url: str, dest_dir: Path, ref: str | None = None) -> Path:
    """Shallow-clone ``clone_url`` into ``dest_dir``.

    When ``ref`` is ``None`` or ``HEAD``, clones the repository default branch
    using ``git clone --depth 1 --single-branch --no-tags``.

    For branch and tag refs, adds ``--branch <ref>`` to that clone command.

    For commit SHAs (7–40 hex characters), uses ``git init`` + shallow
    ``git fetch origin <sha>`` + ``git checkout FETCH_HEAD``.

    ``dest_dir`` is the target working tree path. For branch/tag/default clones
    it must not exist yet (git creates it). For SHA fetch clones, the directory
    is created by ``git init``.

    Returns the resolved path to the cloned working tree.

    Raises GitCloneError on:
    - git binary not found
    - clone/fetch subprocess timeout (60s default)
    - non-zero exit code (network error, private/missing repo, missing ref, etc.)
    """
    if shutil.which("git") is None:
        raise GitCloneError(
            "git executable not found on PATH",
            kind=GitCloneError.KIND_GIT_EXECUTABLE,
        )

    dest = dest_dir.resolve()
    requested_ref = _effective_ref(ref)
    log_ref = requested_ref if requested_ref is not None else "default branch"
    _LOG.info("shallow cloning %s at ref %s into %s", clone_url, log_ref, dest)

    if requested_ref is None:
        _clone_default_branch(clone_url, dest)
    elif _is_commit_sha_ref(requested_ref):
        _clone_commit_sha(clone_url, dest, requested_ref)
    else:
        _clone_branch_or_tag(clone_url, dest, requested_ref)

    return dest
