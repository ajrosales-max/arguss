"""Tests for GET /assessment/{scan_hash}/sbom."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from arguss.core.sbom import CYCLONEDX_SPEC_VERSION
from arguss.web.url_scan import serialize_lockfile_deps
from tests.test_candidate_selection_ui import _cached_scan_dict

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "lockfiles"
_SCAN_HASH = "sbom-download-demo-hash-001"


def _scan_with_deps(
    *,
    mode: str = "A",
    repo_display: str = "expressjs/express",
) -> dict[str, Any]:
    lockfile = _FIXTURES / "minimal.json"
    scan = _cached_scan_dict(entries=[], mode=mode)
    scan["deps"] = serialize_lockfile_deps(lockfile)
    scan["scan_meta"]["repo_display"] = repo_display
    return scan


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def _unique_dep_keys(deps: list[dict[str, Any]]) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    for dep in deps:
        package = str(dep.get("package") or "").strip()
        version = str(dep.get("version") or "").strip()
        if package and version:
            keys.add((package, version))
    return keys


def test_sbom_download_mode_a_returns_cyclonedx_json(client: TestClient) -> None:
    scan = _scan_with_deps()
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get(f"/assessment/{_SCAN_HASH}/sbom")

    assert response.status_code == status.HTTP_200_OK
    assert response.headers["content-type"].startswith("application/json")
    bom = json.loads(response.content)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == CYCLONEDX_SPEC_VERSION
    assert bom["version"] == 1
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert bom["metadata"]["component"]["name"] == "expressjs/express"
    assert isinstance(bom["components"], list)
    assert isinstance(bom["dependencies"], list)


def test_sbom_download_mode_b_returns_cyclonedx_json(client: TestClient) -> None:
    scan = _scan_with_deps(mode="B", repo_display="Uploaded lockfile")
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get(f"/assessment/{_SCAN_HASH}/sbom")

    assert response.status_code == status.HTTP_200_OK
    bom = json.loads(response.content)
    assert bom["specVersion"] == CYCLONEDX_SPEC_VERSION
    assert bom["metadata"]["component"]["name"] == "upload"


def test_sbom_download_content_disposition_mode_a(client: TestClient) -> None:
    scan = _scan_with_deps()
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get(f"/assessment/{_SCAN_HASH}/sbom")

    disposition = response.headers.get("content-disposition", "")
    assert "attachment" in disposition
    assert f"arguss-sbom-expressjs-express-{_SCAN_HASH[:8]}.cdx.json" in disposition


def test_sbom_download_content_disposition_mode_b(client: TestClient) -> None:
    scan = _scan_with_deps(mode="B", repo_display="Uploaded lockfile")
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get(f"/assessment/{_SCAN_HASH}/sbom")

    disposition = response.headers.get("content-disposition", "")
    assert "attachment" in disposition
    assert f"arguss-sbom-upload-{_SCAN_HASH[:8]}.cdx.json" in disposition


def test_sbom_download_missing_cache_returns_404(client: TestClient) -> None:
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=None):
        response = client.get("/assessment/garbage-hash-404/sbom")

    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_sbom_download_component_count_matches_deps(client: TestClient) -> None:
    lockfile = _FIXTURES / "real-world.json"
    scan = _cached_scan_dict(entries=[])
    scan["deps"] = serialize_lockfile_deps(lockfile)
    expected_keys = _unique_dep_keys(scan["deps"])

    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get(f"/assessment/{_SCAN_HASH}/sbom")

    bom = json.loads(response.content)
    component_keys = {(c["name"], c["version"]) for c in bom["components"]}
    assert component_keys == expected_keys
    assert len(bom["components"]) == len(expected_keys)


def test_results_page_has_sbom_download_link(client: TestClient) -> None:
    scan = _scan_with_deps()
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get("/assessment/sbom-link-demo")

    assert response.status_code == status.HTTP_200_OK
    assert "/assessment/sbom-link-demo/sbom" in response.text
    assert "Coming soon" not in response.text
    assert 'data-feature="sbom"' not in response.text
