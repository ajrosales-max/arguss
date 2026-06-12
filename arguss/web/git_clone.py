"""Shallow clone a GitHub repo for analysis."""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

_GIT_CLONE_TIMEOUT_SECONDS = 60
_LOG = logging.getLogger(__name__)


class GitCloneError(Exception):
    """Shallow clone failed (network, repo doesn't exist, permission denied, etc)."""

    KIND_GIT_EXECUTABLE = "git_executable"
    KIND_TIMEOUT = "timeout"
    KIND_CLONE_FAILED = "clone_failed"

    def __init__(self, message: str, *, kind: str = KIND_CLONE_FAILED) -> None:
        super().__init__(message)
        self.kind = kind


def shallow_clone(clone_url: str, dest_dir: Path) -> Path:
    """Shallow-clone ``clone_url`` into ``dest_dir``.

    Uses ``git clone --depth 1 --single-branch --no-tags``. ``dest_dir`` is the
    target working tree path (must not exist yet; git creates it).

    Returns the resolved path to the cloned working tree.

    Raises GitCloneError on:
    - git binary not found
    - clone subprocess timeout (60s default)
    - non-zero exit code (network error, private/missing repo, etc.)
    """
    if shutil.which("git") is None:
        raise GitCloneError(
            "git executable not found on PATH",
            kind=GitCloneError.KIND_GIT_EXECUTABLE,
        )

    dest = dest_dir.resolve()
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

    _LOG.info("shallow cloning %s into %s", clone_url, dest)

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
            f"git clone timed out after {_GIT_CLONE_TIMEOUT_SECONDS} seconds",
            kind=GitCloneError.KIND_TIMEOUT,
        ) from exc

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        message = f"git clone failed with exit code {completed.returncode}"
        if stderr:
            message = f"{message}: {stderr}"
        raise GitCloneError(message)

    return dest
