"""Tests for npm repository URL parsing helpers."""

from __future__ import annotations

from arguss.web.github_url import extract_github_owner_repo


def test_extract_github_owner_repo_git_plus_https() -> None:
    assert extract_github_owner_repo(
        "git+https://github.com/axios/axios.git",
    ) == ("axios", "axios")


def test_extract_github_owner_repo_https_no_dot_git() -> None:
    assert extract_github_owner_repo("https://github.com/axios/axios") == (
        "axios",
        "axios",
    )


def test_extract_github_owner_repo_shorthand_github_colon() -> None:
    assert extract_github_owner_repo("github:axios/axios") == ("axios", "axios")


def test_extract_github_owner_repo_ssh() -> None:
    assert extract_github_owner_repo("git+ssh://git@github.com/axios/axios.git") == (
        "axios",
        "axios",
    )


def test_extract_github_owner_repo_git_protocol() -> None:
    assert extract_github_owner_repo("git://github.com/axios/axios.git") == (
        "axios",
        "axios",
    )


def test_extract_github_owner_repo_gitlab_returns_none() -> None:
    assert extract_github_owner_repo("https://gitlab.com/owner/repo") is None


def test_extract_github_owner_repo_bitbucket_returns_none() -> None:
    assert extract_github_owner_repo("https://bitbucket.org/owner/repo") is None


def test_extract_github_owner_repo_missing_returns_none() -> None:
    assert extract_github_owner_repo(None) is None
    assert extract_github_owner_repo("") is None


def test_extract_github_owner_repo_malformed_returns_none() -> None:
    assert extract_github_owner_repo("not-a-url") is None
    assert extract_github_owner_repo("github:onlyowner") is None


def test_extract_github_owner_repo_dict_form() -> None:
    assert extract_github_owner_repo(
        {"type": "git", "url": "git+https://github.com/axios/axios.git"},
    ) == ("axios", "axios")


def test_extract_github_owner_repo_string_form() -> None:
    assert extract_github_owner_repo("https://github.com/lodash/lodash.git") == (
        "lodash",
        "lodash",
    )
