"""Tests for /assessment/{hash} permalink cache-miss recovery."""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from arguss.web.scan_inputs import ScanInputs, save_scan_inputs
from arguss.web.wizard_session import LAST_SCAN_COOKIE
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict

_HASH = "permalink-recovery-hash"
_URL = "https://github.com/expressjs/express"


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def _mode_a_scan() -> dict[str, Any]:
    return _cached_scan_dict(entries=[_cached_entry(package="left-pad")], mode="A")


def test_assessment_cache_hit_renders_directly_no_rescan(client: TestClient, wizard_db) -> None:
    scan = _mode_a_scan()
    with (
        mock.patch.object(
            dashboard_mod, "get_cached_scan_response", return_value=scan
        ) as get_cache,
        mock.patch.object(dashboard_mod, "_rescan_from_inputs", new=mock.AsyncMock()) as rescan,
    ):
        response = client.get(f"/assessment/{_HASH}")

    assert response.status_code == status.HTTP_200_OK
    get_cache.assert_called_once_with(_HASH)
    rescan.assert_not_called()


def test_assessment_cache_miss_with_mode_a_inputs_triggers_rescan(
    client: TestClient,
    wizard_db,
) -> None:
    save_scan_inputs(_HASH, "A", _URL, "HEAD", wizard_db)
    fresh = _mode_a_scan()
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=None),
        mock.patch.object(
            dashboard_mod, "_rescan_from_inputs", new=mock.AsyncMock(return_value=fresh)
        ) as rescan,
    ):
        response = client.get(f"/assessment/{_HASH}")

    assert response.status_code == status.HTTP_200_OK
    rescan.assert_awaited_once()
    inputs = rescan.await_args.args[0]
    assert isinstance(inputs, ScanInputs)
    assert inputs.mode == "A"
    assert inputs.url == _URL


def test_assessment_cache_miss_with_mode_c_inputs_triggers_rescan(
    client: TestClient,
    wizard_db,
) -> None:
    save_scan_inputs(_HASH, "C", _URL, "main", wizard_db)
    fresh = _cached_scan_dict(entries=[_cached_entry()], mode="C")
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=None),
        mock.patch.object(
            dashboard_mod, "_rescan_from_inputs", new=mock.AsyncMock(return_value=fresh)
        ) as rescan,
    ):
        response = client.get(f"/assessment/{_HASH}")

    assert response.status_code == status.HTTP_200_OK
    rescan.assert_awaited_once()
    assert rescan.await_args.args[0].mode == "C"


def test_assessment_cache_miss_with_mode_b_inputs_shows_upload_expired(
    client: TestClient,
    wizard_db,
) -> None:
    save_scan_inputs(_HASH, "B", "uploaded://lockfile", None, wizard_db)
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=None):
        response = client.get(f"/assessment/{_HASH}")

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "Scan expired" in response.text
    assert "Upload a lockfile again" in response.text


def test_assessment_cache_miss_no_inputs_shows_generic_expired(
    client: TestClient,
    wizard_db,
) -> None:
    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=None):
        response = client.get(f"/assessment/{_HASH}")

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "Scan not found" in response.text
    assert "Run a new scan" in response.text


def test_assessment_rescan_failure_shows_rescan_failed_page(
    client: TestClient,
    wizard_db,
) -> None:
    save_scan_inputs(_HASH, "A", _URL, "HEAD", wizard_db)
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=None),
        mock.patch.object(
            dashboard_mod,
            "_rescan_from_inputs",
            new=mock.AsyncMock(side_effect=RuntimeError("boom")),
        ),
    ):
        response = client.get(f"/assessment/{_HASH}")

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "Couldn't refresh this scan" in response.text
    assert "Run a fresh scan" in response.text


def test_rescan_caches_fresh_result(client: TestClient, wizard_db) -> None:
    save_scan_inputs(_HASH, "A", _URL, "HEAD", wizard_db)
    fresh = _mode_a_scan()
    rescan = mock.AsyncMock(return_value=fresh)
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", side_effect=[None, fresh]),
        mock.patch.object(dashboard_mod, "_rescan_from_inputs", new=rescan),
    ):
        first = client.get(f"/assessment/{_HASH}")
        second = client.get(f"/assessment/{_HASH}")

    assert first.status_code == status.HTTP_200_OK
    assert second.status_code == status.HTTP_200_OK
    rescan.assert_awaited_once()


def test_rescan_does_not_set_last_scan_cookie(client: TestClient, wizard_db) -> None:
    save_scan_inputs(_HASH, "A", _URL, "HEAD", wizard_db)
    fresh = _mode_a_scan()
    with (
        mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=None),
        mock.patch.object(
            dashboard_mod, "_rescan_from_inputs", new=mock.AsyncMock(return_value=fresh)
        ),
    ):
        response = client.get(f"/assessment/{_HASH}")

    assert response.status_code == status.HTTP_200_OK
    assert LAST_SCAN_COOKIE not in response.cookies
