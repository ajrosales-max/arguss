"""Tests for safe workflow zip extraction and POST /scan/upload."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.routes as routes_mod
import arguss.web.zip_safe as zip_safe_mod
from arguss.api import app as api_app
from arguss.engine.propose import ProposalReport, ProposalSummary
from arguss.lenses._zizmor_client import ZizmorClientError
from arguss.settings import Settings
from arguss.settings import settings as live_settings
from arguss.web.zip_safe import ZipExtractionError, extract_workflows_zip

_SCAN_UPLOAD = "/scan/upload"
_INTERNAL_DETAIL = "Internal error during analysis"
_FIXTURES = Path(__file__).parent / "fixtures" / "lockfiles"

_MINIMAL_LOCKFILE = (
    b'{"lockfileVersion": 3, "packages": {"": {"name": "upload-test", "version": "1.0.0"}}}'
)
_V1_LOCKFILE = b'{"lockfileVersion": 1, "dependencies": {}}'
_MINIMAL_PACKAGE_JSON = b'{"name": "upload-test", "version": "1.0.0"}'


@pytest.fixture
def kill_switch_off(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("ARGUSS_KILL_SWITCH", raising=False)
    monkeypatch.setenv("ARGUSS_KILL_SWITCH_FILE_PATH", str(tmp_path / "kill_switch_absent"))


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def _make_zip(
    files: dict[str, bytes] | None = None,
    *,
    symlink: tuple[str, bytes] | None = None,
) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        if files:
            for name, data in files.items():
                zf.writestr(name, data)
        if symlink is not None:
            name, data = symlink
            info = zipfile.ZipInfo(name)
            info.external_attr = 0o120777 << 16
            zf.writestr(info, data)
    return buf.getvalue()


def _minimal_proposal_report(repo: Path) -> ProposalReport:
    lockfile = repo / "package-lock.json"
    return ProposalReport(
        repo_path=str(repo),
        lockfile_path=str(lockfile),
        entries=(),
        skipped_findings=(),
        summary=ProposalSummary(
            total_findings=0,
            total_candidates=0,
            auto_merge_count=0,
            review_required_count=0,
            decline_count=0,
        ),
    )


# --- Zip safety (14) ---


def test_extract_workflows_zip_extracts_valid_yml_files(tmp_path: Path) -> None:
    dest = tmp_path / "workflows"
    data = _make_zip({"ci.yml": b"name: ci\n", "deploy.yaml": b"name: deploy\n"})
    count = extract_workflows_zip(data, dest)
    assert count == 2
    assert (dest / "ci.yml").read_text() == "name: ci\n"
    assert (dest / "deploy.yaml").read_text() == "name: deploy\n"


def test_extract_workflows_zip_strips_directory_prefix(tmp_path: Path) -> None:
    dest = tmp_path / "workflows"
    data = _make_zip({"workflows/ci.yml": b"steps: []\n"})
    extract_workflows_zip(data, dest)
    assert (dest / "ci.yml").is_file()
    assert not (dest / "workflows").exists()


def test_extract_workflows_zip_accepts_yaml_extension(tmp_path: Path) -> None:
    dest = tmp_path / "workflows"
    data = _make_zip({"lint.yaml": b"on: push\n"})
    assert extract_workflows_zip(data, dest) == 1
    assert (dest / "lint.yaml").is_file()


def test_extract_workflows_zip_rejects_non_yaml(tmp_path: Path) -> None:
    dest = tmp_path / "workflows"
    data = _make_zip({"run.sh": b"#!/bin/sh\n"})
    with pytest.raises(ZipExtractionError, match=r"\.yml or \.yaml"):
        extract_workflows_zip(data, dest)


def test_extract_workflows_zip_rejects_path_traversal(tmp_path: Path) -> None:
    dest = tmp_path / "workflows"
    data = _make_zip({"../escaped.yml": b"x: 1\n"})
    with pytest.raises(ZipExtractionError, match="path traversal"):
        extract_workflows_zip(data, dest)


def test_extract_workflows_zip_rejects_absolute_path(tmp_path: Path) -> None:
    dest = tmp_path / "workflows"
    data = _make_zip({"/etc/passwd.yml": b"x: 1\n"})
    with pytest.raises(ZipExtractionError, match="absolute path"):
        extract_workflows_zip(data, dest)


def test_extract_workflows_zip_rejects_backslash(tmp_path: Path) -> None:
    dest = tmp_path / "workflows"
    data = _make_zip({r"dir\evil.yml": b"x: 1\n"})
    with pytest.raises(ZipExtractionError, match="backslash"):
        extract_workflows_zip(data, dest)


def test_extract_workflows_zip_rejects_symlink_entry(tmp_path: Path) -> None:
    dest = tmp_path / "workflows"
    data = _make_zip(symlink=("link.yml", b"target"))
    with pytest.raises(ZipExtractionError, match="symlink"):
        extract_workflows_zip(data, dest)


def test_extract_workflows_zip_rejects_too_many_entries(tmp_path: Path) -> None:
    dest = tmp_path / "workflows"
    files = {f"f{i}.yml": b"x: 1\n" for i in range(zip_safe_mod._MAX_ENTRIES + 1)}
    data = _make_zip(files)
    with pytest.raises(ZipExtractionError, match="more than"):
        extract_workflows_zip(data, dest)


def test_extract_workflows_zip_rejects_oversized_entry(tmp_path: Path) -> None:
    dest = tmp_path / "workflows"
    oversized = b"x" * (zip_safe_mod._MAX_PER_FILE_BYTES + 1)
    data = _make_zip({"big.yml": oversized})
    with pytest.raises(ZipExtractionError, match="per-file size limit"):
        extract_workflows_zip(data, dest)


def test_extract_workflows_zip_rejects_oversized_total(tmp_path: Path) -> None:
    dest = tmp_path / "workflows"
    chunk = b"x" * zip_safe_mod._MAX_PER_FILE_BYTES
    files = {f"f{i}.yml": chunk for i in range(6)}
    data = _make_zip(files)
    with pytest.raises(ZipExtractionError, match="total uncompressed size limit"):
        extract_workflows_zip(data, dest)


def test_extract_workflows_zip_rejects_invalid_zip(tmp_path: Path) -> None:
    dest = tmp_path / "workflows"
    with pytest.raises(ZipExtractionError, match="not a valid zip"):
        extract_workflows_zip(b"not a zip file", dest)


def test_extract_workflows_zip_rejects_empty_zip(tmp_path: Path) -> None:
    dest = tmp_path / "workflows"
    data = _make_zip()
    with pytest.raises(ZipExtractionError, match="no workflow files"):
        extract_workflows_zip(data, dest)


def test_extract_workflows_zip_skips_directory_entries(tmp_path: Path) -> None:
    dest = tmp_path / "workflows"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("workflows/", "")
        zf.writestr("workflows/ci.yml", b"name: ci\n")
    count = extract_workflows_zip(buf.getvalue(), dest)
    assert count == 1
    assert (dest / "ci.yml").is_file()


def test_extract_workflows_zip_ignores_macos_metadata_files(tmp_path: Path) -> None:
    """macOS Finder metadata entries are skipped; real workflow files are extracted."""
    dest = tmp_path / "workflows"
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr(".github/workflows/ci.yml", "name: CI\non: push\njobs: {}\n")
        zf.writestr("__MACOSX/.github/workflows/._ci.yml", b"\x00\x05\x16\x07")
        zf.writestr(".github/workflows/._ci.yml", b"\x00\x05\x16\x07")
        zf.writestr("._workflows", b"\x00\x05\x16\x07")
    count = extract_workflows_zip(zip_buf.getvalue(), dest)
    assert count == 1
    assert (dest / "ci.yml").is_file()


# --- Endpoint (12) ---


def test_scan_upload_minimal_lockfile_only_returns_200(
    client: TestClient,
    tmp_path: Path,
) -> None:
    fake_report = _minimal_proposal_report(tmp_path / "repo")

    with mock.patch.object(routes_mod, "propose_fixes", return_value=fake_report):
        response = client.post(
            _SCAN_UPLOAD,
            files={"lockfile": ("package-lock.json", _MINIMAL_LOCKFILE, "application/json")},
        )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert set(data.keys()) == {
        "repo_path",
        "lockfile_path",
        "entries",
        "skipped_findings",
        "summary",
        "executive_summary",
        "project_scores",
    }


def test_scan_upload_with_all_three_files_returns_200(
    client: TestClient,
    tmp_path: Path,
) -> None:
    fake_report = _minimal_proposal_report(tmp_path / "repo")
    workflows_zip = _make_zip({"workflows/ci.yml": b"name: ci\n"})
    layout: dict[str, object] = {}

    def capture_repo(lockfile_path: Path, repo_path: Path) -> ProposalReport:
        layout["lockfile_path"] = lockfile_path
        layout["package_json"] = (repo_path / "package.json").read_text(encoding="utf-8")
        layout["workflow"] = (repo_path / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8",
        )
        return fake_report

    with mock.patch.object(routes_mod, "propose_fixes", side_effect=capture_repo):
        response = client.post(
            _SCAN_UPLOAD,
            files=[
                ("lockfile", ("package-lock.json", _MINIMAL_LOCKFILE, "application/json")),
                ("workflows_zip", ("workflows.zip", workflows_zip, "application/zip")),
                ("package_json", ("package.json", _MINIMAL_PACKAGE_JSON, "application/json")),
            ],
        )

    assert response.status_code == status.HTTP_200_OK
    assert layout["lockfile_path"].name == "package-lock.json"  # type: ignore[union-attr]
    assert layout["package_json"] == _MINIMAL_PACKAGE_JSON.decode()
    assert layout["workflow"] == "name: ci\n"


def test_scan_upload_missing_lockfile_returns_422(client: TestClient) -> None:
    response = client.post(_SCAN_UPLOAD, files={})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


def test_scan_upload_lockfile_too_large_returns_413(client: TestClient) -> None:
    with mock.patch.object(routes_mod, "_MAX_LOCKFILE_BYTES", 100):
        response = client.post(
            _SCAN_UPLOAD,
            files={"lockfile": ("package-lock.json", b"x" * 101, "application/json")},
        )
    assert response.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    assert "lockfile" in response.json()["detail"]


def test_scan_upload_workflows_zip_too_large_returns_413(client: TestClient) -> None:
    with mock.patch.object(routes_mod, "_MAX_WORKFLOWS_ZIP_BYTES", 50):
        response = client.post(
            _SCAN_UPLOAD,
            files=[
                ("lockfile", ("package-lock.json", _MINIMAL_LOCKFILE, "application/json")),
                ("workflows_zip", ("workflows.zip", b"z" * 51, "application/zip")),
            ],
        )
    assert response.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    assert "workflows_zip" in response.json()["detail"]


def test_scan_upload_package_json_too_large_returns_413(client: TestClient) -> None:
    with mock.patch.object(routes_mod, "_MAX_PACKAGE_JSON_BYTES", 50):
        response = client.post(
            _SCAN_UPLOAD,
            files=[
                ("lockfile", ("package-lock.json", _MINIMAL_LOCKFILE, "application/json")),
                ("package_json", ("package.json", b"j" * 51, "application/json")),
            ],
        )
    assert response.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    assert "package_json" in response.json()["detail"]


def test_scan_upload_invalid_lockfile_json_returns_422(client: TestClient) -> None:
    response = client.post(
        _SCAN_UPLOAD,
        files={"lockfile": ("package-lock.json", b"not json", "application/json")},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert response.json()["detail"] == "lockfile is not valid JSON"


def test_scan_upload_invalid_package_json_returns_422(client: TestClient) -> None:
    response = client.post(
        _SCAN_UPLOAD,
        files=[
            ("lockfile", ("package-lock.json", _MINIMAL_LOCKFILE, "application/json")),
            ("package_json", ("package.json", b"{not valid", "application/json")),
        ],
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert response.json()["detail"] == "package_json is not valid JSON"


def test_scan_upload_v1_lockfile_returns_422(client: TestClient) -> None:
    response = client.post(
        _SCAN_UPLOAD,
        files={"lockfile": ("package-lock.json", _V1_LOCKFILE, "application/json")},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    detail = response.json()["detail"]
    assert detail.startswith("Could not parse lockfile:")
    assert "lockfile version 1" in detail.lower() or "lockfileVersion" in detail


def test_scan_upload_malicious_zip_returns_422(client: TestClient) -> None:
    malicious_zip = _make_zip({"../evil.yml": b"x: 1\n"})
    response = client.post(
        _SCAN_UPLOAD,
        files=[
            ("lockfile", ("package-lock.json", _MINIMAL_LOCKFILE, "application/json")),
            ("workflows_zip", ("workflows.zip", malicious_zip, "application/zip")),
        ],
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    detail = response.json()["detail"]
    assert "path traversal" in detail
    assert "/etc" not in detail


@pytest.mark.parametrize(
    "side_effect",
    [
        ZizmorClientError("zizmor failed"),
        RuntimeError("unexpected boom"),
    ],
)
def test_scan_upload_internal_error_returns_500(
    client: TestClient,
    side_effect: BaseException,
) -> None:
    with mock.patch.object(routes_mod, "propose_fixes", side_effect=side_effect):
        response = client.post(
            _SCAN_UPLOAD,
            files={"lockfile": ("package-lock.json", _MINIMAL_LOCKFILE, "application/json")},
        )

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert response.json()["detail"] == _INTERNAL_DETAIL
    assert "traceback" not in response.text.lower()
    assert "RuntimeError" not in response.text
    assert "ZizmorClientError" not in response.text


def test_scan_upload_tempdir_cleaned_up(
    client: TestClient,
    tmp_path: Path,
) -> None:
    recorded: list[Path] = []
    fake_report = _minimal_proposal_report(tmp_path / "repo")

    def capture_repo(lockfile_path: Path, repo_path: Path) -> ProposalReport:
        recorded.append(Path(repo_path))
        return fake_report

    with mock.patch.object(routes_mod, "propose_fixes", side_effect=capture_repo):
        response = client.post(
            _SCAN_UPLOAD,
            files={"lockfile": ("package-lock.json", _MINIMAL_LOCKFILE, "application/json")},
        )

    assert response.status_code == status.HTTP_200_OK
    assert len(recorded) == 1
    assert not recorded[0].exists()


# --- Integration ---


@pytest.mark.integration
def test_scan_upload_integration_with_real_fixture(
    client: TestClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kill_switch_off: None,
) -> None:
    """End-to-end: real lockfile fixture, real OSV, real propose_fixes."""
    db = tmp_path / "scan_upload_integration.db"
    monkeypatch.setattr(live_settings, "db_path", db)
    monkeypatch.setattr(Settings, "db_path", db)

    lockfile_bytes = (_FIXTURES / "real-world.json").read_bytes()
    response = client.post(
        _SCAN_UPLOAD,
        files={"lockfile": ("package-lock.json", lockfile_bytes, "application/json")},
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert set(data.keys()) == {
        "repo_path",
        "lockfile_path",
        "entries",
        "skipped_findings",
        "summary",
        "executive_summary",
        "project_scores",
    }
    assert isinstance(data["entries"], list)
    assert len(data["entries"]) >= 1
    summary = data["summary"]
    assert summary["total_candidates"] == len(data["entries"])
    assert summary["total_findings"] >= 1
