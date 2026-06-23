"""Tests for the /top-packages dashboard page."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.api as api_mod
import arguss.settings as settings_mod
import arguss.web.auth as auth_mod
from arguss.api import create_app
from arguss.core.cache import get_connection, init_db
from arguss.settings import Settings
from arguss.web.dashboard import _top_packages_context

_SWEPT_AT = "2026-06-01T12:00:00Z"
_INSERT = """
INSERT INTO top_packages (
    rank, name, historical_advisory_count, historical_advisory_ids,
    latest_version, latest_vulnerable, latest_advisories, swept_at,
    previously_vulnerable_version, patched_advisory_ids, max_epss, is_malware
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _seed_top_packages(db_path: Path, rows: list[tuple]) -> None:
    conn = get_connection(db_path)
    init_db(conn)
    try:
        for row in rows:
            conn.execute(_INSERT, row)
        conn.commit()
    finally:
        conn.close()


def _patch_db(monkeypatch: pytest.MonkeyPatch, db_path: Path) -> None:
    monkeypatch.setattr(settings_mod.settings, "db_path", db_path)
    monkeypatch.setattr(Settings, "db_path", db_path)


@pytest.fixture
def auth_client(monkeypatch: pytest.MonkeyPatch) -> Callable[..., TestClient]:
    """Build a fresh app after patching demo auth settings."""

    def _factory(
        *,
        demo_password: str | None = None,
        demo_username: str = "demo",
    ) -> TestClient:
        monkeypatch.setattr(Settings, "demo_username", demo_username)
        monkeypatch.setattr(Settings, "demo_password", demo_password)
        patched = Settings()
        monkeypatch.setattr(settings_mod, "settings", patched)
        monkeypatch.setattr(auth_mod, "settings", patched)
        monkeypatch.setattr(api_mod, "settings", patched)
        return TestClient(create_app())

    return _factory


def test_top_packages_context_counts(tmp_path: Path) -> None:
    db = tmp_path / "ctx.db"
    advisories = json.dumps([{"id": "GHSA-abc", "summary": "Example issue"}])
    _seed_top_packages(
        db,
        [
            (
                1,
                "vuln-pkg",
                2,
                json.dumps(["GHSA-1"]),
                "1.0.0",
                1,
                advisories,
                _SWEPT_AT,
                "0.9.0",
                json.dumps(["GHSA-1"]),
                None,
                0,
            ),
            (
                2,
                "safe-pkg",
                0,
                json.dumps([]),
                "2.0.0",
                0,
                json.dumps([]),
                _SWEPT_AT,
                None,
                None,
                None,
                0,
            ),
            (
                3,
                "unknown-pkg",
                1,
                json.dumps(["GHSA-2"]),
                None,
                None,
                None,
                _SWEPT_AT,
                None,
                None,
                None,
                None,
            ),
        ],
    )

    ctx = _top_packages_context(db)

    assert ctx["total"] == 3
    assert ctx["prev_vuln_count"] == 1
    assert ctx["swept_at"] == _SWEPT_AT
    assert ctx["is_empty"] is False
    assert ctx["packages"][0].name == "vuln-pkg"
    assert ctx["packages"][0].previously_vulnerable_version == "0.9.0"
    assert ctx["packages"][0].latest_advisories[0]["id"] == "GHSA-abc"


def test_top_packages_page_populated(
    monkeypatch: pytest.MonkeyPatch,
    auth_client: Callable[..., TestClient],
    tmp_path: Path,
) -> None:
    db = tmp_path / "page.db"
    _patch_db(monkeypatch, db)
    _seed_top_packages(
        db,
        [
            (
                1,
                "lodash",
                5,
                json.dumps(["GHSA-x"]),
                "4.17.21",
                1,
                json.dumps([]),
                _SWEPT_AT,
                "4.17.20",
                json.dumps(["GHSA-x"]),
                None,
                0,
            ),
            (
                2,
                "left-pad",
                0,
                json.dumps([]),
                "1.3.0",
                0,
                json.dumps([]),
                _SWEPT_AT,
                None,
                None,
                None,
                0,
            ),
        ],
    )

    client = auth_client(demo_password=None)
    response = client.get("/top-packages")

    assert response.status_code == status.HTTP_200_OK
    body = response.text
    assert "1 with a patched advisory of 2" in body
    assert _SWEPT_AT in body
    assert 'data-testid="top-packages-banner"' in body
    assert "lodash" in body
    assert "4.17.20" in body
    assert 'data-testid="top-packages-empty"' not in body


def test_top_packages_page_empty(
    monkeypatch: pytest.MonkeyPatch,
    auth_client: Callable[..., TestClient],
    tmp_path: Path,
) -> None:
    db = tmp_path / "empty.db"
    _patch_db(monkeypatch, db)
    conn = get_connection(db)
    init_db(conn)
    conn.close()

    client = auth_client(demo_password=None)
    response = client.get("/top-packages")

    assert response.status_code == status.HTTP_200_OK
    body = response.text
    assert 'data-testid="top-packages-empty"' in body
    assert "arguss sweep-top-1000" in body
    assert "0 with a patched advisory of 0" in body


def test_top_packages_page_renders_zero_epss(
    monkeypatch: pytest.MonkeyPatch,
    auth_client: Callable[..., TestClient],
    tmp_path: Path,
) -> None:
    db = tmp_path / "epss-zero.db"
    _patch_db(monkeypatch, db)
    _seed_top_packages(
        db,
        [
            (
                1,
                "zero-epss-pkg",
                1,
                json.dumps(["GHSA-z"]),
                "2.0.0",
                0,
                json.dumps([]),
                _SWEPT_AT,
                "1.0.0",
                json.dumps(["GHSA-z"]),
                0.0,
                0,
            ),
        ],
    )

    client = auth_client(demo_password=None)
    response = client.get("/top-packages")

    assert response.status_code == status.HTTP_200_OK
    body = response.text
    assert "0.00" in body
    assert ">—<" not in body.replace(" ", "")


def test_top_packages_page_renders_malware_badge(
    monkeypatch: pytest.MonkeyPatch,
    auth_client: Callable[..., TestClient],
    tmp_path: Path,
) -> None:
    db = tmp_path / "malware.db"
    _patch_db(monkeypatch, db)
    _seed_top_packages(
        db,
        [
            (
                1,
                "malware-pkg",
                0,
                json.dumps([]),
                "1.0.0",
                0,
                json.dumps([]),
                _SWEPT_AT,
                None,
                None,
                0.12,
                1,
            ),
        ],
    )

    client = auth_client(demo_password=None)
    response = client.get("/top-packages")

    assert response.status_code == status.HTTP_200_OK
    body = response.text
    assert ">Malware<" in body
    assert (
        "EPSS estimates exploitation probability of a disclosed vulnerability; "
        "it does not characterize malware injected via account takeover."
    ) in body
    assert "0.12" in body


def test_top_packages_requires_auth_when_demo_password_set(
    auth_client: Callable[..., TestClient],
) -> None:
    client = auth_client(demo_password="testpass")
    response = client.get("/top-packages")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.headers.get("www-authenticate") == 'Basic realm="Arguss"'


def test_top_packages_open_with_credentials(
    auth_client: Callable[..., TestClient],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    db = tmp_path / "auth.db"
    _patch_db(monkeypatch, db)
    conn = get_connection(db)
    init_db(conn)
    conn.close()

    client = auth_client(demo_password="testpass")
    response = client.get("/top-packages", auth=("demo", "testpass"))

    assert response.status_code == status.HTTP_200_OK
    assert "text/html" in response.headers["content-type"]
