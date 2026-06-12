"""Tests for ref-aware shallow_clone (Step 2)."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from unittest import mock

import pytest

import arguss.web.git_clone as git_clone_mod
from arguss.web.git_clone import GitCloneError, shallow_clone

_CLONE_URL = "https://github.com/o/r.git"


def _git_ok() -> mock.Mock:
    return mock.Mock(returncode=0, stdout="", stderr="")


@pytest.fixture(autouse=True)
def _git_on_path() -> mock.Mock:
    with mock.patch.object(git_clone_mod.shutil, "which", return_value="/usr/bin/git"):
        yield


def test_shallow_clone_default_branch_omits_branch_flag(tmp_path: Path) -> None:
    dest = tmp_path / "repo"
    with mock.patch.object(git_clone_mod.subprocess, "run") as run:
        run.return_value = _git_ok()
        shallow_clone(_CLONE_URL, dest)

    cmd = run.call_args.args[0]
    assert "--branch" not in cmd


@pytest.mark.parametrize("ref", [None, "HEAD", "  head  "])
def test_shallow_clone_head_refs_use_default_clone(
    tmp_path: Path,
    ref: str | None,
) -> None:
    dest = tmp_path / "repo"
    with mock.patch.object(git_clone_mod.subprocess, "run") as run:
        run.return_value = _git_ok()
        shallow_clone(_CLONE_URL, dest, ref=ref)

    cmd = run.call_args.args[0]
    assert cmd[:4] == ["git", "clone", "--depth", "1"]
    assert "--branch" not in cmd


@pytest.mark.parametrize("ref", ["main", "v1.0.0"])
def test_shallow_clone_branch_and_tag_include_branch_flag(
    tmp_path: Path,
    ref: str,
) -> None:
    dest = tmp_path / "repo"
    with mock.patch.object(git_clone_mod.subprocess, "run") as run:
        run.return_value = _git_ok()
        shallow_clone(_CLONE_URL, dest, ref=ref)

    cmd = run.call_args.args[0]
    branch_idx = cmd.index("--branch")
    assert cmd[branch_idx + 1] == ref


def test_shallow_clone_commit_sha_uses_fetch_path(tmp_path: Path) -> None:
    dest = tmp_path / "repo"
    sha = "e2d9f3366b5603ba"
    with mock.patch.object(git_clone_mod.subprocess, "run") as run:
        run.return_value = _git_ok()
        shallow_clone(_CLONE_URL, dest, ref=sha)

    assert run.call_count == 4
    init_cmd = run.call_args_list[0].args[0]
    fetch_cmd = run.call_args_list[2].args[0]
    checkout_cmd = run.call_args_list[3].args[0]
    assert init_cmd == ["git", "init", str(dest.resolve())]
    assert fetch_cmd == [
        "git",
        "-C",
        str(dest.resolve()),
        "fetch",
        "--depth",
        "1",
        "origin",
        sha,
    ]
    assert checkout_cmd == ["git", "-C", str(dest.resolve()), "checkout", "FETCH_HEAD"]


def test_shallow_clone_missing_ref_raises_ref_not_found(tmp_path: Path) -> None:
    dest = tmp_path / "repo"
    stderr = "fatal: Remote branch v1.0.0 not found in upstream origin"
    with mock.patch.object(git_clone_mod.subprocess, "run") as run:
        run.return_value = mock.Mock(returncode=128, stdout="", stderr=stderr)
        with pytest.raises(GitCloneError) as exc_info:
            shallow_clone(_CLONE_URL, dest, ref="v1.0.0")

    exc = exc_info.value
    assert exc.kind == GitCloneError.KIND_REF_NOT_FOUND
    assert exc.ref == "v1.0.0"


def test_shallow_clone_generic_failure_stays_clone_failed(tmp_path: Path) -> None:
    dest = tmp_path / "repo"
    with mock.patch.object(git_clone_mod.subprocess, "run") as run:
        run.return_value = mock.Mock(
            returncode=128,
            stdout="",
            stderr="fatal: repository not found",
        )
        with pytest.raises(GitCloneError) as exc_info:
            shallow_clone(_CLONE_URL, dest, ref="main")

    assert exc_info.value.kind == GitCloneError.KIND_CLONE_FAILED


def test_shallow_clone_timeout_kind_unchanged(tmp_path: Path) -> None:
    dest = tmp_path / "repo"
    with mock.patch.object(git_clone_mod.subprocess, "run") as run:
        run.side_effect = subprocess.TimeoutExpired(cmd=["git", "clone"], timeout=60)
        with pytest.raises(GitCloneError) as exc_info:
            shallow_clone(_CLONE_URL, dest, ref="main")

    assert exc_info.value.kind == GitCloneError.KIND_TIMEOUT


def test_shallow_clone_log_includes_ref(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    dest = tmp_path / "repo"
    with (
        caplog.at_level(logging.INFO, logger="arguss.web.git_clone"),
        mock.patch.object(git_clone_mod.subprocess, "run", return_value=_git_ok()),
    ):
        shallow_clone(_CLONE_URL, dest, ref="v1.0.0")

    assert any(
        "shallow cloning" in r.getMessage() and "v1.0.0" in r.getMessage() for r in caplog.records
    )
