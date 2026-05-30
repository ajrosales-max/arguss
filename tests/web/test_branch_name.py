"""Tests for deterministic GitHub branch name derivation."""

from __future__ import annotations

from arguss.core.models import FixCandidate, FixKind
from arguss.web import github_action as ga


def _candidate(
    *,
    package: str = "simple-git",
    from_version: str = "3.28.0",
    to_version: str = "3.36.0",
) -> FixCandidate:
    return FixCandidate(
        package=package,
        from_version=from_version,
        to_version=to_version,
        fix_kind=FixKind.MINOR,
        source_finding_ids=("GHSA-test",),
        repo_id="/tmp/repo",
    )


def test_branch_name_plain_package() -> None:
    candidate = _candidate(package="simple-git", from_version="3.28.0", to_version="3.36.0")
    assert ga._derive_branch_name(candidate) == "arguss/upgrade-simple-git-3.28.0-to-3.36.0"


def test_branch_name_scoped_package_drops_at_and_replaces_slash() -> None:
    candidate = _candidate(
        package="@isaacs/brace-expansion",
        from_version="1.0.0",
        to_version="1.0.1",
    )
    assert (
        ga._derive_branch_name(candidate) == "arguss/upgrade-isaacs-brace-expansion-1.0.0-to-1.0.1"
    )


def test_branch_name_preserves_dots_in_version() -> None:
    candidate = _candidate(package="minimatch", from_version="9.0.5", to_version="9.0.7")
    assert ga._derive_branch_name(candidate) == "arguss/upgrade-minimatch-9.0.5-to-9.0.7"


def test_branch_name_idempotent() -> None:
    c1 = _candidate(package="yaml", from_version="2.8.1", to_version="2.8.3")
    c2 = _candidate(package="yaml", from_version="2.8.1", to_version="2.8.3")
    assert ga._derive_branch_name(c1) == ga._derive_branch_name(c2)


def test_branch_name_under_git_ref_limit() -> None:
    long_package = "a" * 200
    candidate = _candidate(package=long_package, from_version="1.0.0", to_version="2.0.0")
    branch = ga._derive_branch_name(candidate)
    assert len(branch) <= 250
    assert ga._is_valid_git_branch_ref(branch)
