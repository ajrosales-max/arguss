"""Integration tests for live GitHub API fetch."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from arguss.web.github_fetch import fetch_repo_inputs


@pytest.mark.integration
@pytest.mark.asyncio
async def test_fetch_repo_inputs_live_axios(tmp_path: Path) -> None:
    """Real GitHub API call against a small public repo with package-lock.json."""
    dest = tmp_path / "axios"
    result = await fetch_repo_inputs("axios", "axios", "HEAD", dest)

    assert result.lockfile_path.is_file()
    assert (dest / "package-lock.json").stat().st_size > 0
    assert (dest / "package.json").is_file()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_fetch_repo_inputs_live_axios_large_lockfile(tmp_path: Path) -> None:
    """Live fetch when package-lock.json exceeds the Contents API 1 MB limit."""
    dest = tmp_path / "axios-v1"
    await fetch_repo_inputs("axios", "axios", "v1.0.0", dest)

    lockfile = dest / "package-lock.json"
    assert lockfile.is_file()
    assert lockfile.stat().st_size > 1_000_000
    json.loads(lockfile.read_text(encoding="utf-8"))
