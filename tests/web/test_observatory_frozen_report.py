"""Tests for GET /observatory/report/{hash} frozen Observatory reports."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from arguss.api import app as api_app
from arguss.web import observatory_seed as observatory_seed_mod

_FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "observatory_reports"
_FIXTURE_HASH = "747a96cd083927d6d7c889ed7799b707ff1f06adc5cbf6575b785a502e7b5b1c"
_UNKNOWN_VALID_HASH = "a" * 64


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


@pytest.fixture
def reports_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    dest = tmp_path / "observatory-reports"
    dest.mkdir()
    for path in _FIXTURE_DIR.glob("*.json"):
        (dest / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(observatory_seed_mod, "default_reports_dir", lambda: dest)
    return dest


def test_frozen_report_renders_fixture(client: TestClient, reports_dir: Path) -> None:
    response = client.get(f"/observatory/report/{_FIXTURE_HASH}")

    assert response.status_code == status.HTTP_200_OK
    assert "fixture/observatory-frozen" in response.text
    assert "Executive summary unavailable" not in response.text
    assert 'class="exec-summary"' not in response.text


def test_frozen_report_unknown_hash_returns_styled_404(
    client: TestClient,
    reports_dir: Path,
) -> None:
    response = client.get(f"/observatory/report/{_UNKNOWN_VALID_HASH}")

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "Report not found" in response.text
    assert _UNKNOWN_VALID_HASH in response.text
    assert "Back to Observatory" in response.text


@pytest.mark.parametrize(
    "bad_hash",
    [
        "deadbeef",
        "G" * 64,
        "." * 64,
        "a" * 63 + "z",
    ],
)
def test_frozen_report_rejects_malformed_hash_without_reading(
    client: TestClient,
    reports_dir: Path,
    bad_hash: str,
) -> None:
    trap = reports_dir / f"{bad_hash}.json"
    trap.write_text('{"trap": true}', encoding="utf-8")

    with mock.patch.object(Path, "read_text", wraps=Path.read_text) as read_text:
        response = client.get(f"/observatory/report/{bad_hash}")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    for call in read_text.call_args_list:
        called_path = call.args[0] if call.args else None
        if isinstance(called_path, Path) and called_path.parent == reports_dir:
            pytest.fail("report loader read from reports dir for malformed hash")


def test_load_observatory_report_validates_before_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="invalid observatory report hash"):
        observatory_seed_mod.load_observatory_report("../not-a-hash")


def test_load_observatory_report_rejects_path_traversal_hash() -> None:
    with pytest.raises(ValueError, match="invalid observatory report hash"):
        observatory_seed_mod.load_observatory_report(".." + "a" * 62)
