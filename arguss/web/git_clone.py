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
        raise GitCloneError("git executable not found on PATH")

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
    except subprocess.TimeoutExpired as exc:
        raise GitCloneError(
            f"git clone timed out after {_GIT_CLONE_TIMEOUT_SECONDS} seconds"
        ) from exc

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        message = f"git clone failed with exit code {completed.returncode}"
        if stderr:
            message = f"{message}: {stderr}"
        raise GitCloneError(message)

    return dest
