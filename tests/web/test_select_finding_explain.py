"""Plumbing tests for Explain verdict on the select-candidates page."""

from __future__ import annotations

import re
from unittest import mock

import pytest
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from arguss.core.models import Finding
from tests.test_candidate_selection_ui import _cached_scan_dict
from tests.web.conftest import open_wizard_select
from tests.web.test_candidate_findings_drilldown import _entry, _rf

_HEX16 = re.compile(r"^[a-f0-9]{16}$")


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def _primary_finding_id(entry: dict) -> str:
    finding_raw = entry["finding"]
    fid = finding_raw.get("finding_id")
    if isinstance(fid, str) and fid:
        return fid
    return Finding.model_validate(finding_raw).finding_id


def test_select_explain_buttons_use_primary_finding_id_for_all_rows(client, wizard_db) -> None:
    related = [_rf("GHSA-a", 9.0), _rf("GHSA-b", 7.0)]
    entry = _entry("lodash", related)
    primary_id = _primary_finding_id(entry)
    assert _HEX16.fullmatch(primary_id)
    scan = _cached_scan_dict(entries=[entry])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = open_wizard_select(client, "explain-primary-id", scan)

    assert response.text.count("Explain this verdict") == 2
    assert response.text.count(f'"finding_id": "{primary_id}"') == 2
    assert '"finding_id": "GHSA-a"' not in response.text
    assert '"finding_id": "GHSA-b"' not in response.text


def test_select_explain_panel_ids_are_unique_per_row(client, wizard_db) -> None:
    related = [_rf("GHSA-a", 9.0), _rf("GHSA-b", 7.0)]
    entry = _entry("lodash", related)
    cid = entry["candidate"]["candidate_id"]
    scan = _cached_scan_dict(entries=[entry])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = open_wizard_select(client, "explain-panel-ids", scan)

    panel_ids = [
        f'id="finding-explain-{cid}-GHSA-a"',
        f'id="finding-explain-{cid}-GHSA-b"',
    ]
    for panel_id in panel_ids:
        assert panel_id in response.text
    assert response.text.count(f'id="finding-explain-{cid}-') == 2


def test_build_candidates_by_tier_sets_primary_finding_id_on_related_rows() -> None:
    from arguss.web.results_context import build_candidates_by_tier

    related = [_rf("GHSA-a", 9.0), _rf("GHSA-b", 7.0)]
    entry = _entry("lodash", related)
    primary_id = _primary_finding_id(entry)
    candidate = build_candidates_by_tier({"entries": [entry]})["auto_merge"][0]
    assert len(candidate.findings) == 2
    assert all(f.finding_id == primary_id for f in candidate.findings)


def test_select_explain_buttons_request_version_risks_section(client, wizard_db) -> None:
    related = [_rf("GHSA-a", 9.0), _rf("GHSA-b", 7.0)]
    entry = _entry("lodash", related)
    scan = _cached_scan_dict(entries=[entry])
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = open_wizard_select(client, "explain-version-risks", scan)

    assert '"include_version_risks": "1"' in response.text
    assert response.text.count('"include_version_risks": "1"') == 2
