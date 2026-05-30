"""Unit tests for lockfile fix helpers and apply_fix_to_lockfile."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from arguss.core.models import FixCandidate, FixKind
from arguss.lenses._trust_client import TrustClientError
from arguss.web.lockfile_fix import (
    LockfileModificationError,
    _bump_range,
    _update_package_json_version,
    apply_fix_to_lockfile,
    classify_dep_position,
    find_lockfile_entries,
    parse_lockfile_bytes,
)

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "lockfiles"


def _candidate(
    *,
    package: str = "left-pad",
    from_version: str = "1.3.0",
    to_version: str = "1.3.1",
) -> FixCandidate:
    return FixCandidate(
        package=package,
        from_version=from_version,
        to_version=to_version,
        fix_kind=FixKind.PATCH,
        source_finding_ids=("GHSA-test",),
        repo_id="/tmp/repo",
    )


def _npm_client(dist_by_version: dict[tuple[str, str], dict[str, str]]) -> mock.MagicMock:
    client = mock.MagicMock()

    def _fetch(package: str, version: str) -> dict[str, Any]:
        dist = dist_by_version.get((package, version))
        if dist is None:
            raise TrustClientError(f"npm registry: {package}@{version} not found")
        return {"dist": dist}

    client.fetch_version_metadata.side_effect = _fetch
    return client


def _left_pad_dist(version: str) -> dict[str, str]:
    return {
        "tarball": f"https://registry.npmjs.org/left-pad/-/left-pad-{version}.tgz",
        "integrity": f"sha512-leftpad-{version}",
    }


def _minimal_package_json() -> dict[str, Any]:
    return {
        "name": "minimal-test",
        "version": "1.0.0",
        "dependencies": {"left-pad": "1.3.0"},
    }


def test_classify_dep_position_direct_in_dependencies() -> None:
    pkg = {"dependencies": {"foo": "^1.0.0"}}
    assert classify_dep_position("foo", pkg) == "direct"


def test_classify_dep_position_direct_in_devDependencies() -> None:
    pkg = {"devDependencies": {"eslint": "^8.0.0"}}
    assert classify_dep_position("eslint", pkg) == "direct"


def test_classify_dep_position_transitive_returns_correct_label() -> None:
    pkg = {"dependencies": {"express": "^4.0.0"}}
    assert classify_dep_position("qs", pkg) == "transitive"


def test_classify_dep_position_scoped_package() -> None:
    pkg = {"dependencies": {"@scope/pkg": "^1.0.0"}}
    assert classify_dep_position("@scope/pkg", pkg) == "direct"
    assert classify_dep_position("pkg", pkg) == "transitive"


def test_find_lockfile_entries_single_hoisted() -> None:
    lockfile = {
        "packages": {
            "node_modules/foo": {"version": "1.0.0"},
        },
    }
    assert find_lockfile_entries(lockfile, "foo", "1.0.0") == ["node_modules/foo"]


def test_find_lockfile_entries_multiple_nested() -> None:
    lockfile = {
        "packages": {
            "node_modules/minimatch": {"version": "9.0.5"},
            "node_modules/glob/node_modules/minimatch": {"version": "9.0.5"},
            "node_modules/a/node_modules/b/node_modules/minimatch": {"version": "9.0.5"},
            "node_modules/minimatch/node_modules/other": {"version": "1.0.0"},
        },
    }
    keys = find_lockfile_entries(lockfile, "minimatch", "9.0.5")
    assert len(keys) == 3
    assert "node_modules/minimatch" in keys
    assert "node_modules/glob/node_modules/minimatch" in keys


def test_find_lockfile_entries_filters_by_version() -> None:
    lockfile = {
        "packages": {
            "node_modules/minimatch": {"version": "9.0.5"},
            "node_modules/glob/node_modules/minimatch": {"version": "9.0.7"},
        },
    }
    assert find_lockfile_entries(lockfile, "minimatch", "9.0.5") == ["node_modules/minimatch"]


def test_find_lockfile_entries_scoped_package() -> None:
    lockfile = {
        "packages": {
            "node_modules/@isaacs/brace-expansion": {"version": "2.0.1"},
            "node_modules/foo/node_modules/@isaacs/brace-expansion": {"version": "2.0.1"},
        },
    }
    keys = find_lockfile_entries(lockfile, "@isaacs/brace-expansion", "2.0.1")
    assert len(keys) == 2


def test_apply_fix_transitive_proceeds_with_lockfile_only_update() -> None:
    lockfile = json.loads((_FIXTURES / "with-transitive.json").read_text(encoding="utf-8"))
    package_json = {"dependencies": {"express": "^4.0.0"}}
    package_json_before = json.loads(json.dumps(package_json))
    candidate = _candidate(package="chalk", from_version="4.1.2", to_version="4.1.3")
    npm = _npm_client(
        {
            ("chalk", "4.1.3"): {
                "tarball": "https://registry.npmjs.org/chalk/-/chalk-4.1.3.tgz",
                "integrity": "sha512-chalk",
            },
        },
    )

    result = apply_fix_to_lockfile(lockfile, package_json, candidate, npm)

    assert result.applied is True
    assert result.files_modified == ("package-lock.json",)
    assert package_json == package_json_before
    assert lockfile["packages"]["node_modules/chalk"]["version"] == "4.1.3"


def test_apply_fix_direct_dep_updates_both_files() -> None:
    lockfile = json.loads((_FIXTURES / "minimal.json").read_text(encoding="utf-8"))
    package_json = _minimal_package_json()
    candidate = _candidate()
    npm = _npm_client({("left-pad", "1.3.1"): _left_pad_dist("1.3.1")})

    result = apply_fix_to_lockfile(lockfile, package_json, candidate, npm)

    assert result.applied is True
    assert result.files_modified == ("package.json", "package-lock.json")


def test_apply_fix_direct_updates_all_matching_entries() -> None:
    lockfile = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"minimatch": "^9.0.5"}},
            "node_modules/minimatch": {
                "version": "9.0.5",
                "resolved": "https://registry.npmjs.org/minimatch/-/minimatch-9.0.5.tgz",
                "integrity": "sha512-old",
            },
            "node_modules/glob/node_modules/minimatch": {
                "version": "9.0.5",
                "resolved": "https://registry.npmjs.org/minimatch/-/minimatch-9.0.5.tgz",
                "integrity": "sha512-old",
            },
        },
    }
    package_json = {"dependencies": {"minimatch": "^9.0.5"}}
    candidate = _candidate(package="minimatch", from_version="9.0.5", to_version="9.0.7")
    dist = {
        "tarball": "https://registry.npmjs.org/minimatch/-/minimatch-9.0.7.tgz",
        "integrity": "sha512-new",
    }
    npm = _npm_client({("minimatch", "9.0.7"): dist})

    result = apply_fix_to_lockfile(lockfile, package_json, candidate, npm)

    assert result.applied is True
    assert len(result.entries_updated) == 2
    assert result.files_modified == ("package.json", "package-lock.json")
    assert result.files_modified == ("package.json", "package-lock.json")
    for key in result.entries_updated:
        entry = lockfile["packages"][key]
        assert entry["version"] == "9.0.7"
        assert entry["integrity"] == "sha512-new"
        assert "9.0.7" in entry["resolved"]
    assert package_json["dependencies"]["minimatch"] == "^9.0.7"


def test_apply_fix_updates_package_json_range_preserving_prefix() -> None:
    package_json = {"dependencies": {"minimatch": "^9.0.5"}}
    assert _bump_range("^9.0.5", "9.0.7") == "^9.0.7"
    _update_package_json_version(package_json, "minimatch", "9.0.7")
    assert package_json["dependencies"]["minimatch"] == "^9.0.7"


def test_apply_fix_unrecognized_range_pins_exact() -> None:
    package_json = {"dependencies": {"foo": "workspace:*"}}
    _update_package_json_version(package_json, "foo", "2.0.0")
    assert package_json["dependencies"]["foo"] == "2.0.0"


def test_apply_fix_fetches_integrity_from_npm_registry() -> None:
    lockfile = json.loads((_FIXTURES / "minimal.json").read_text(encoding="utf-8"))
    package_json = _minimal_package_json()
    candidate = _candidate()
    npm = _npm_client({("left-pad", "1.3.1"): _left_pad_dist("1.3.1")})

    result = apply_fix_to_lockfile(lockfile, package_json, candidate, npm)

    assert result.applied is True
    entry = lockfile["packages"]["node_modules/left-pad"]
    assert entry["integrity"] == "sha512-leftpad-1.3.1"
    npm.fetch_version_metadata.assert_called_once_with("left-pad", "1.3.1")


def test_apply_fix_handles_npm_registry_failure_gracefully() -> None:
    lockfile = json.loads((_FIXTURES / "minimal.json").read_text(encoding="utf-8"))
    package_json = _minimal_package_json()
    candidate = _candidate()
    npm = mock.MagicMock()
    npm.fetch_version_metadata.side_effect = TrustClientError("network down")

    result = apply_fix_to_lockfile(lockfile, package_json, candidate, npm)

    assert result.applied is False
    assert result.skipped_reason is not None
    assert "could not fetch left-pad@1.3.1 from npm registry" in result.skipped_reason


def test_apply_fix_no_matching_entry_skips_with_clear_reason() -> None:
    lockfile = json.loads((_FIXTURES / "minimal.json").read_text(encoding="utf-8"))
    package_json = _minimal_package_json()
    candidate = _candidate(from_version="9.9.9")
    npm = _npm_client({("left-pad", "1.3.1"): _left_pad_dist("1.3.1")})

    result = apply_fix_to_lockfile(lockfile, package_json, candidate, npm)

    assert result.applied is False
    assert result.skipped_reason is not None
    assert "no lockfile entry found for left-pad@9.9.9" in result.skipped_reason


def test_apply_fix_caret_range_preserved() -> None:
    assert _bump_range("^9.0.5", "9.0.7") == "^9.0.7"


def test_apply_fix_tilde_range_preserved() -> None:
    assert _bump_range("~9.0.5", "9.0.7") == "~9.0.7"


def test_apply_fix_simple_direct_dep() -> None:
    lockfile = json.loads((_FIXTURES / "minimal.json").read_text(encoding="utf-8"))
    package_json = _minimal_package_json()
    candidate = _candidate()
    npm = _npm_client({("left-pad", "1.3.1"): _left_pad_dist("1.3.1")})

    result = apply_fix_to_lockfile(lockfile, package_json, candidate, npm)

    assert result.applied is True
    assert lockfile["packages"]["node_modules/left-pad"]["version"] == "1.3.1"
    assert lockfile["packages"][""]["dependencies"]["left-pad"] == "1.3.1"


def test_apply_fix_nested_direct_dep_with_child_packages() -> None:
    lockfile = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"foo": "1.0.0"}},
            "node_modules/foo": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
            },
            "node_modules/foo/node_modules/bar": {
                "version": "2.0.0",
                "resolved": "https://registry.npmjs.org/bar/-/bar-2.0.0.tgz",
            },
        },
    }
    package_json = {"dependencies": {"foo": "1.0.0"}}
    candidate = _candidate(package="foo", from_version="1.0.0", to_version="1.0.1")
    npm = _npm_client(
        {
            ("foo", "1.0.1"): {
                "tarball": "https://registry.npmjs.org/foo/-/foo-1.0.1.tgz",
                "integrity": "sha512-foo",
            },
        },
    )

    result = apply_fix_to_lockfile(lockfile, package_json, candidate, npm)

    assert result.applied is True
    assert lockfile["packages"]["node_modules/foo"]["version"] == "1.0.1"
    assert lockfile["packages"]["node_modules/foo/node_modules/bar"]["version"] == "2.0.0"


def test_parse_lockfile_bytes_malformed_raises() -> None:
    with pytest.raises(LockfileModificationError, match="not valid JSON"):
        parse_lockfile_bytes(b"{not json")
