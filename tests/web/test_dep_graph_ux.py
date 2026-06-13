"""Tests for dependency graph panel UX and graph element payloads."""

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
from arguss.web.graph_data import build_full_graph_elements
from arguss.web.url_scan import serialize_lockfile_deps
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "lockfiles"
_SCAN_HASH = "dep-graph-ux-demo"


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def _enriched_deps() -> list[dict[str, Any]]:
    return serialize_lockfile_deps(_FIXTURES / "real-world.json")


def _results_html(client: TestClient) -> str:
    entry = _cached_entry(package="debug")
    entry["finding"]["dependency"]["version"] = "2.6.9"
    scan = _cached_scan_dict(entries=[entry])
    scan["deps"] = _enriched_deps()
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = client.get(f"/assessment/{_SCAN_HASH}")
    assert response.status_code == status.HTTP_200_OK
    return response.text


def test_dep_graph_panel_has_expand_and_tooltip(client: TestClient) -> None:
    html = _results_html(client)
    section_start = html.index('class="dependency-graph-section"')
    section_end = html.index("</section>", section_start)
    section = html[section_start:section_end]
    assert 'id="dependency-graph-expand"' in section
    assert 'id="dependency-graph-tooltip"' in section


def test_subgraph_still_renders_package_blast_radius(client: TestClient) -> None:
    html = _results_html(client)
    assert 'class="package-blast-radius"' in html
    assert "package-blast-radius-data" in html
    assert "bootBlastRadiusGraphs" in html


def test_full_graph_element_data_fields() -> None:
    deps = _enriched_deps()
    findings = [{"severity": "high", "dependency": {"name": "debug", "version": "2.6.9"}}]
    trust = {"express": {"trust_score": 72, "trust_concern": "Branch-Protection (3)"}}
    elements = build_full_graph_elements(deps, findings, trust_by_package=trust)
    nodes = [el for el in elements if "source" not in el["data"]]
    express = next(n for n in nodes if n["data"]["id"] == "express")
    debug = next(n for n in nodes if n["data"]["id"] == "debug")
    for key in ("id", "label", "version", "vuln_count", "max_severity", "has_vuln"):
        assert key in express["data"]
        assert key in debug["data"]
    assert express["data"]["trust_score"] == 72
    assert debug["data"]["has_vuln"] is True


def test_results_page_graph_json_includes_node_fields(client: TestClient) -> None:
    html = _results_html(client)
    marker = 'id="dependency-graph-data"'
    start = html.index(marker)
    json_start = html.index(">", start) + 1
    json_end = html.index("</script>", json_start)
    elements = json.loads(html[json_start:json_end])
    nodes = [el for el in elements if "source" not in el["data"]]
    debug = next(n for n in nodes if n["data"]["id"] == "debug")
    for key in ("id", "label", "version", "vuln_count", "max_severity", "has_vuln"):
        assert key in debug["data"]
