"""Tests for JSON indent detection and preservation on lockfile roundtrip."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

from arguss.core.models import FixCandidate, FixKind
from arguss.web.lockfile_fix import (
    apply_fix_to_lockfile,
    detect_json_indent,
    encode_lockfile,
    encode_package_json,
    parse_lockfile_bytes,
)

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "lockfiles"


def _candidate() -> FixCandidate:
    return FixCandidate(
        package="left-pad",
        from_version="1.3.0",
        to_version="1.3.1",
        fix_kind=FixKind.PATCH,
        source_finding_ids=("GHSA-test",),
        repo_id="/tmp/repo",
    )


def _npm_client() -> mock.MagicMock:
    client = mock.MagicMock()
    client.fetch_version_metadata.return_value = {
        "dist": {
            "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.1.tgz",
            "integrity": "sha512-new",
        },
    }
    return client


def test_detect_indent_two_spaces() -> None:
    src = '{\n  "key": "value"\n}\n'
    assert detect_json_indent(src) == 2


def test_detect_indent_four_spaces() -> None:
    src = '{\n    "key": "value"\n}\n'
    assert detect_json_indent(src) == 4


def test_detect_indent_tabs() -> None:
    src = '{\n\t"key": "value"\n}\n'
    assert detect_json_indent(src) == "\t"


def test_detect_indent_empty_object_defaults_to_two() -> None:
    src = "{}"
    assert detect_json_indent(src) == 2


def test_detect_indent_handles_bom() -> None:
    src = '\ufeff{\n    "key": "value"\n}'
    assert detect_json_indent(src) == 4


def test_detect_indent_handles_bytes_input() -> None:
    assert detect_json_indent(b'{\n    "k": 1\n}') == 4


def test_detect_indent_handles_leading_blank_lines() -> None:
    src = '\n\n{\n  "k": 1\n}'
    assert detect_json_indent(src) == 2


def test_apply_fix_preserves_four_space_indent() -> None:
    original_bytes = (_FIXTURES / "minimal-four-space.json").read_bytes()
    lockfile = parse_lockfile_bytes(original_bytes)
    package_json = {"dependencies": {"left-pad": "1.3.0"}}

    result = apply_fix_to_lockfile(lockfile, package_json, _candidate(), _npm_client())
    assert result.applied is True

    result_bytes = encode_lockfile(lockfile, original_bytes)
    assert detect_json_indent(result_bytes) == 4


def test_apply_fix_preserves_two_space_indent() -> None:
    original_bytes = (_FIXTURES / "minimal.json").read_bytes()
    lockfile = parse_lockfile_bytes(original_bytes)
    package_json = {"dependencies": {"left-pad": "1.3.0"}}
    package_json_bytes = b'{\n  "dependencies": {\n    "left-pad": "1.3.0"\n  }\n}\n'

    apply_fix_to_lockfile(lockfile, package_json, _candidate(), _npm_client())

    assert detect_json_indent(encode_lockfile(lockfile, original_bytes)) == 2
    assert detect_json_indent(encode_package_json(package_json, package_json_bytes)) == 2


def test_apply_fix_preserves_trailing_newline() -> None:
    original_bytes = (_FIXTURES / "minimal-four-space.json").read_bytes()
    lockfile = parse_lockfile_bytes(original_bytes)
    apply_fix_to_lockfile(
        lockfile, {"dependencies": {"left-pad": "1.3.0"}}, _candidate(), _npm_client()
    )

    result_bytes = encode_lockfile(lockfile, original_bytes)
    assert original_bytes.endswith(b"\n")
    assert result_bytes.endswith(b"\n")


def test_apply_fix_no_trailing_newline_when_input_has_none() -> None:
    original_bytes = b'{\n  "lockfileVersion": 3,\n  "packages": {}\n}'
    lockfile = parse_lockfile_bytes(original_bytes)
    result_bytes = encode_lockfile(lockfile, original_bytes)
    assert not result_bytes.endswith(b"\n")


def test_apply_fix_no_unicode_escape_when_ascii() -> None:
    original_bytes = (_FIXTURES / "minimal-four-space.json").read_bytes()
    lockfile = parse_lockfile_bytes(original_bytes)
    apply_fix_to_lockfile(
        lockfile, {"dependencies": {"left-pad": "1.3.0"}}, _candidate(), _npm_client()
    )

    result_text = encode_lockfile(lockfile, original_bytes).decode("utf-8")
    assert "café" in result_text
    assert "\\u" not in result_text
