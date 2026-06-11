"""Tests for scan_inputs persistence."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
from arguss.api import app as api_app
from arguss.settings import settings
from arguss.web.scan_inputs import load_scan_inputs, save_scan_inputs


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def test_save_scan_inputs_persists_url_and_ref(wizard_db) -> None:
    save_scan_inputs("abc123", "A", "https://github.com/o/r", "main", wizard_db)
    loaded = load_scan_inputs("abc123", wizard_db)
    assert loaded is not None
    assert loaded.scan_hash == "abc123"
    assert loaded.mode == "A"
    assert loaded.url == "https://github.com/o/r"
    assert loaded.ref == "main"


def test_save_scan_inputs_is_idempotent(wizard_db) -> None:
    save_scan_inputs("idem", "A", "https://github.com/o/r", "HEAD", wizard_db)
    first = load_scan_inputs("idem", wizard_db)
    assert first is not None
    save_scan_inputs("idem", "A", "https://github.com/o/r2", "dev", wizard_db)
    second = load_scan_inputs("idem", wizard_db)
    assert second is not None
    assert second.url == "https://github.com/o/r2"
    assert second.ref == "dev"


def test_load_scan_inputs_returns_none_for_unknown_hash(wizard_db) -> None:
    assert load_scan_inputs("missing", wizard_db) is None


def test_save_skips_mode_b(wizard_db, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "db_path", wizard_db)
    saved: list[tuple] = []

    def _track(*args, **kwargs):
        saved.append(args)

    monkeypatch.setattr(dashboard_mod, "save_scan_inputs", _track)
    monkeypatch.setattr(
        dashboard_mod,
        "attach_executive_summary",
        lambda payload: {**payload, "executive_summary": "stub"},
    )
    monkeypatch.setattr(dashboard_mod, "compute_scan_input_hash", lambda _p: "hash-b")

    payload = {
        "scan_meta": {"mode": "B", "repo_display": "Uploaded lockfile", "ref": "—"},
        "entries": [],
    }
    dashboard_mod._hx_redirect_response(payload, persist_url="ignored", persist_ref=None)

    assert saved == []
