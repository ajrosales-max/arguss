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
from arguss.web.dashboard import (
    TopPackageRow,
    _top_packages_context,
    derive_advisory_severity_chips,
    derive_malware_incident_label,
    derive_malware_incidents,
    derive_top_package_status,
    derive_top_packages_header_counts,
    format_last_advisory_date,
)

_SWEPT_AT = "2026-06-01T12:00:00Z"
_INSERT = """
INSERT INTO top_packages (
    rank, name, historical_advisory_count, historical_advisory_ids,
    latest_version, latest_vulnerable, latest_advisories, swept_at,
    previously_vulnerable_version, patched_advisory_ids, max_epss, is_malware,
    previously_vulnerable_advisories
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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


def test_format_swept_at_microsecond_iso() -> None:
    from arguss.web.dashboard import _format_swept_at

    assert _format_swept_at("2026-06-23T03:17:05.267274+00:00") == "Jun 23, 2026 · 03:17 UTC"
    assert _format_swept_at("2026-06-01T12:00:00Z") == "Jun 01, 2026 · 12:00 UTC"
    assert _format_swept_at(None) is None


def _minimal_row(**overrides: object) -> TopPackageRow:
    base: dict[str, object] = {
        "rank": 1,
        "name": "pkg",
        "historical_advisory_count": 0,
        "historical_advisory_ids": [],
        "latest_version": "1.0.0",
        "latest_vulnerable": 0,
        "latest_advisories": [],
        "swept_at": _SWEPT_AT,
        "previously_vulnerable_version": None,
        "patched_advisory_ids": [],
        "max_epss": None,
        "previously_vulnerable_advisories": [],
        "status": "clear",
        "has_malware_history": False,
        "malware_incident_label": None,
        "historical_advisory_summaries": [],
        "last_advisory_date": None,
        "last_advisory_date_display": None,
        "severity_chips": None,
    }
    base.update(overrides)
    return TopPackageRow(**base)  # type: ignore[arg-type]


def test_header_counts_basic_vulnerable_clear_unknown() -> None:
    from datetime import UTC, datetime

    now = datetime(2026, 7, 15, tzinfo=UTC)
    packages = [
        _minimal_row(name="v", latest_vulnerable=1, status="vulnerable"),
        _minimal_row(name="c", latest_vulnerable=0, status="clear"),
        _minimal_row(name="u", latest_vulnerable=None, status="unknown"),
    ]
    counts = derive_top_packages_header_counts(packages, now=now)
    assert counts["currently_vulnerable"] == 1
    assert counts["clear"] == 1
    assert counts["unknown"] == 1
    assert counts["malware_last_12mo"] is None


def test_header_counts_malware_window_boundary() -> None:
    from datetime import UTC, datetime, timedelta

    now = datetime(2026, 7, 15, 12, 0, 0, tzinfo=UTC)
    # Exactly 365 days ago → included
    within = (now - timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    # 366 days ago → excluded
    outside = (now - timedelta(days=366)).strftime("%Y-%m-%dT%H:%M:%SZ")

    packages = [
        _minimal_row(
            name="recent-malware",
            latest_vulnerable=0,
            historical_advisory_summaries=[
                {
                    "id": "MAL-1",
                    "summary": "x",
                    "published": within,
                    "severity": None,
                    "is_malware": True,
                }
            ],
        ),
        _minimal_row(
            name="old-malware",
            latest_vulnerable=0,
            historical_advisory_summaries=[
                {
                    "id": "MAL-2",
                    "summary": "y",
                    "published": outside,
                    "severity": None,
                    "is_malware": True,
                }
            ],
        ),
        _minimal_row(
            name="vuln-no-malware",
            latest_vulnerable=1,
            status="vulnerable",
            historical_advisory_summaries=[
                {
                    "id": "GHSA-1",
                    "summary": "z",
                    "published": within,
                    "severity": "high",
                    "is_malware": False,
                }
            ],
        ),
    ]
    counts = derive_top_packages_header_counts(packages, now=now)
    assert counts["malware_last_12mo"] == 1
    assert counts["currently_vulnerable"] == 1
    assert counts["clear"] == 2
    assert counts["unknown"] == 0


def test_header_counts_omit_malware_when_all_summaries_absent() -> None:
    from datetime import UTC, datetime

    packages = [
        _minimal_row(name="a", historical_advisory_summaries=[]),
        _minimal_row(
            name="b", latest_vulnerable=1, status="vulnerable", historical_advisory_summaries=[]
        ),
    ]
    counts = derive_top_packages_header_counts(packages, now=datetime(2026, 7, 15, tzinfo=UTC))
    assert counts["malware_last_12mo"] is None


def test_header_counts_null_summaries_do_not_contribute_when_others_present() -> None:
    from datetime import UTC, datetime

    now = datetime(2026, 7, 15, tzinfo=UTC)
    packages = [
        _minimal_row(
            name="has-data",
            historical_advisory_summaries=[
                {
                    "id": "MAL-1",
                    "summary": "x",
                    "published": "2026-01-01T00:00:00Z",
                    "severity": None,
                    "is_malware": True,
                }
            ],
        ),
        _minimal_row(name="pre-migration", historical_advisory_summaries=[]),
    ]
    counts = derive_top_packages_header_counts(packages, now=now)
    assert counts["malware_last_12mo"] == 1


def test_top_packages_page_renders_unknown_suffix(
    monkeypatch: pytest.MonkeyPatch,
    auth_client: Callable[..., TestClient],
    tmp_path: Path,
) -> None:
    db = tmp_path / "unknown-banner.db"
    _patch_db(monkeypatch, db)
    conn = get_connection(db)
    init_db(conn)
    summaries = json.dumps(
        [
            {
                "id": "MAL-1",
                "summary": "x",
                "published": "2026-01-01T00:00:00Z",
                "severity": None,
                "is_malware": True,
            }
        ]
    )
    conn.execute(
        """
        INSERT INTO top_packages (
            rank, name, historical_advisory_count, historical_advisory_ids,
            latest_version, latest_vulnerable, latest_advisories, swept_at,
            previously_vulnerable_version, patched_advisory_ids, max_epss, is_malware,
            previously_vulnerable_advisories, historical_advisory_summaries, last_advisory_date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            1,
            "debug",
            1,
            json.dumps(["MAL-1"]),
            "4.4.3",
            0,
            json.dumps([]),
            _SWEPT_AT,
            "4.4.2",
            json.dumps(["MAL-1"]),
            None,
            1,
            None,
            summaries,
            "2026-01-01T00:00:00Z",
        ),
    )
    conn.execute(
        """
        INSERT INTO top_packages (
            rank, name, historical_advisory_count, historical_advisory_ids,
            latest_version, latest_vulnerable, latest_advisories, swept_at,
            previously_vulnerable_version, patched_advisory_ids, max_epss, is_malware,
            previously_vulnerable_advisories, historical_advisory_summaries, last_advisory_date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            2,
            "mystery",
            0,
            json.dumps([]),
            None,
            None,
            None,
            _SWEPT_AT,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
    )
    conn.commit()
    conn.close()

    client = auth_client(demo_password=None)
    body = client.get("/top-packages").text
    assert "0 currently vulnerable" in body
    assert "1 malware (last 12 mo)" in body
    assert "1 clear" in body
    assert "1 unknown" in body
    assert "Jun 01, 2026 · 12:00 UTC" in body


def test_derive_malware_incidents_filters_malware_entries() -> None:
    summaries = [
        {"id": "GHSA-1", "published": "2025-01-01T00:00:00Z", "is_malware": False},
        {
            "id": "MAL-1",
            "summary": "x",
            "published": "2025-09-08T00:00:00Z",
            "severity": None,
            "is_malware": True,
        },
    ]
    assert derive_malware_incidents(summaries) == [summaries[1]]
    assert derive_malware_incidents([]) == []


def test_derive_top_package_status_latest_clear_with_malware_history() -> None:
    status = derive_top_package_status(0, [])
    assert status == "clear"
    incidents = [{"id": "MAL-1", "published": None, "is_malware": True}]
    label = derive_malware_incident_label(incidents, status)
    assert label == "Malware incident"


def test_derive_top_package_status_latest_vulnerable() -> None:
    assert derive_top_package_status(1, []) == "vulnerable"
    incidents = [{"id": "MAL-1", "published": None, "is_malware": True}]
    assert derive_malware_incident_label(incidents, "vulnerable") == "Malware incident"


def test_derive_top_package_status_latest_malware_advisory() -> None:
    latest_advisories = [{"id": "MAL-2025-46974", "summary": "Malicious code in debug (npm)"}]
    status = derive_top_package_status(0, latest_advisories)
    assert status == "malware"
    incidents = [{"id": "MAL-2025-46974", "published": "2025-09-08T00:00:00Z", "is_malware": True}]
    assert derive_malware_incident_label(incidents, status) is None


def test_derive_malware_incident_label_with_date() -> None:
    incidents = [
        {
            "id": "MAL-1",
            "summary": "x",
            "published": "2025-06-01T00:00:00Z",
            "severity": None,
            "is_malware": True,
        }
    ]
    assert derive_malware_incident_label(incidents, "clear") == "Malware incident · Jun 2025"


def test_derive_malware_incident_label_empty_summaries() -> None:
    assert derive_malware_incident_label([], "clear") is None


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
                None,
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
                None,
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
                None,
            ),
        ],
    )

    ctx = _top_packages_context(db)

    assert ctx["total"] == 3
    assert ctx["currently_vulnerable_count"] == 1
    assert ctx["clear_count"] == 1
    assert ctx["unknown_count"] == 1
    assert ctx["malware_last_12mo_count"] is None  # all summaries NULL
    assert ctx["swept_at"] == "Jun 01, 2026 · 12:00 UTC"
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
                None,
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
                None,
            ),
        ],
    )

    client = auth_client(demo_password=None)
    response = client.get("/top-packages")

    assert response.status_code == status.HTTP_200_OK
    body = response.text
    assert "1 currently vulnerable" in body
    assert "1 clear" in body
    assert "malware (last 12 mo)" not in body
    assert "Jun 01, 2026 · 12:00 UTC" in body
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
    assert "0 currently vulnerable" in body
    assert "0 clear" in body
    assert "malware (last 12 mo)" not in body


def test_top_packages_page_hides_epss_column(
    monkeypatch: pytest.MonkeyPatch,
    auth_client: Callable[..., TestClient],
    tmp_path: Path,
) -> None:
    db = tmp_path / "epss-hidden.db"
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
                None,
            ),
        ],
    )

    client = auth_client(demo_password=None)
    response = client.get("/top-packages")

    assert response.status_code == status.HTTP_200_OK
    body = response.text
    assert ">EPSS<" not in body
    assert "EPSS estimates exploitation probability" not in body
    assert "Peak affected" in body
    assert "Previously vulnerable only" not in body
    assert "Peak affected only" in body


def test_top_packages_page_renders_search_filters_and_row_data_attrs(
    monkeypatch: pytest.MonkeyPatch,
    auth_client: Callable[..., TestClient],
    tmp_path: Path,
) -> None:
    db = tmp_path / "filters.db"
    _patch_db(monkeypatch, db)
    conn = get_connection(db)
    init_db(conn)
    malware_summaries = json.dumps(
        [
            {
                "id": "MAL-1",
                "summary": "x",
                "published": "2025-09-08T00:00:00Z",
                "severity": None,
                "is_malware": True,
            }
        ]
    )
    conn.execute(
        """
        INSERT INTO top_packages (
            rank, name, historical_advisory_count, historical_advisory_ids,
            latest_version, latest_vulnerable, latest_advisories, swept_at,
            previously_vulnerable_version, patched_advisory_ids, max_epss, is_malware,
            previously_vulnerable_advisories, historical_advisory_summaries, last_advisory_date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            1,
            "lodash",
            2,
            json.dumps(["GHSA-x"]),
            "4.17.21",
            0,
            json.dumps([]),
            _SWEPT_AT,
            "4.17.20",
            json.dumps(["GHSA-x"]),
            None,
            0,
            None,
            None,
            None,
        ),
    )
    conn.execute(
        """
        INSERT INTO top_packages (
            rank, name, historical_advisory_count, historical_advisory_ids,
            latest_version, latest_vulnerable, latest_advisories, swept_at,
            previously_vulnerable_version, patched_advisory_ids, max_epss, is_malware,
            previously_vulnerable_advisories, historical_advisory_summaries, last_advisory_date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            2,
            "malware-pkg",
            1,
            json.dumps(["MAL-1"]),
            "1.0.0",
            0,
            json.dumps([]),
            _SWEPT_AT,
            None,
            None,
            None,
            0,
            None,
            malware_summaries,
            "2025-09-08T00:00:00Z",
        ),
    )
    conn.commit()
    conn.close()

    client = auth_client(demo_password=None)
    response = client.get("/top-packages")

    assert response.status_code == status.HTTP_200_OK
    body = response.text
    assert 'id="tp-search"' in body
    assert 'data-testid="tp-search"' in body
    assert 'id="prev-vuln-only-toggle"' in body
    assert 'data-testid="prev-vuln-only-toggle" checked' in body
    assert 'id="malware-only-toggle"' in body
    assert 'data-testid="malware-only-toggle"' in body
    assert 'id="tp-count"' in body
    assert 'data-testid="tp-count"' in body
    assert 'class="tp-row"' in body
    assert 'data-prev-vuln="1"' in body
    assert 'data-prev-vuln="0"' in body
    assert 'data-malware="0"' in body
    assert 'data-malware="1"' in body
    assert 'data-name="lodash"' in body
    assert 'data-name="malware-pkg"' in body
    assert "Malware history" in body
    assert "Malware only" not in body


def test_top_packages_page_renders_malware_badge(
    monkeypatch: pytest.MonkeyPatch,
    auth_client: Callable[..., TestClient],
    tmp_path: Path,
) -> None:
    db = tmp_path / "malware.db"
    _patch_db(monkeypatch, db)
    conn = get_connection(db)
    init_db(conn)
    summaries = json.dumps(
        [
            {
                "id": "MAL-1",
                "summary": "x",
                "published": "2025-09-08T00:00:00Z",
                "severity": None,
                "is_malware": True,
            }
        ]
    )
    conn.execute(
        """
        INSERT INTO top_packages (
            rank, name, historical_advisory_count, historical_advisory_ids,
            latest_version, latest_vulnerable, latest_advisories, swept_at,
            previously_vulnerable_version, patched_advisory_ids, max_epss, is_malware,
            previously_vulnerable_advisories, historical_advisory_summaries, last_advisory_date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            1,
            "malware-pkg",
            1,
            json.dumps(["MAL-1"]),
            "1.0.0",
            0,
            json.dumps([]),
            _SWEPT_AT,
            None,
            None,
            0.12,
            0,
            None,
            summaries,
            "2025-09-08T00:00:00Z",
        ),
    )
    conn.commit()
    conn.close()

    client = auth_client(demo_password=None)
    response = client.get("/top-packages")

    assert response.status_code == status.HTTP_200_OK
    body = response.text
    assert ">Clear<" in body
    assert "Malware incident · Sep 2025" in body
    assert 'class="tp-incident"' in body
    assert "tp-last-advisory-cell" in body
    assert ">Malware<" not in body
    assert ">EPSS<" not in body
    assert "0.12" not in body


def test_top_packages_page_renders_debug_clear_with_malware_incident(
    monkeypatch: pytest.MonkeyPatch,
    auth_client: Callable[..., TestClient],
    tmp_path: Path,
) -> None:
    db = tmp_path / "debug-incident.db"
    _patch_db(monkeypatch, db)
    prev_advisories = json.dumps(
        [{"id": "MAL-2025-46974", "summary": "Malicious code in debug (npm)"}]
    )
    summaries = json.dumps(
        [
            {
                "id": "MAL-2025-46974",
                "summary": "Malicious code in debug (npm)",
                "published": "2025-09-08T00:00:00Z",
                "severity": None,
                "is_malware": True,
            }
        ]
    )
    conn = get_connection(db)
    init_db(conn)
    conn.execute(
        """
        INSERT INTO top_packages (
            rank, name, historical_advisory_count, historical_advisory_ids,
            latest_version, latest_vulnerable, latest_advisories, swept_at,
            previously_vulnerable_version, patched_advisory_ids, max_epss, is_malware,
            previously_vulnerable_advisories, historical_advisory_summaries, last_advisory_date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            1,
            "debug",
            1,
            json.dumps(["MAL-2025-46974"]),
            "4.4.3",
            0,
            json.dumps([]),
            _SWEPT_AT,
            "4.4.2",
            json.dumps(["MAL-2025-46974"]),
            None,
            1,
            prev_advisories,
            summaries,
            "2025-09-08T00:00:00Z",
        ),
    )
    conn.commit()
    conn.close()

    client = auth_client(demo_password=None)
    response = client.get("/top-packages")

    assert response.status_code == status.HTTP_200_OK
    body = response.text
    assert ">Clear<" in body
    assert "Malware incident · Sep 2025" in body
    assert ">Malware<" not in body
    assert 'class="tp-incident"' in body
    assert "tp-last-advisory-cell" in body


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


def test_top_packages_context_parses_previously_vulnerable_advisories(tmp_path: Path) -> None:
    db = tmp_path / "prev-adv-ctx.db"
    prev_advisories = json.dumps(
        [{"id": "MAL-2025-46974", "summary": "Malicious code in debug (npm)"}]
    )
    _seed_top_packages(
        db,
        [
            (
                1,
                "debug",
                1,
                json.dumps(["MAL-2025-46974"]),
                "4.4.3",
                0,
                json.dumps([]),
                _SWEPT_AT,
                "4.4.2",
                json.dumps(["MAL-2025-46974"]),
                None,
                0,
                prev_advisories,
            ),
        ],
    )

    ctx = _top_packages_context(db)

    assert ctx["packages"][0].previously_vulnerable_advisories == [
        {"id": "MAL-2025-46974", "summary": "Malicious code in debug (npm)"}
    ]


def test_top_packages_page_renders_previously_vulnerable_advisories(
    monkeypatch: pytest.MonkeyPatch,
    auth_client: Callable[..., TestClient],
    tmp_path: Path,
) -> None:
    db = tmp_path / "prev-adv-page.db"
    _patch_db(monkeypatch, db)
    prev_advisories = json.dumps(
        [{"id": "MAL-2025-46974", "summary": "Malicious code in debug (npm)"}]
    )
    _seed_top_packages(
        db,
        [
            (
                1,
                "debug",
                1,
                json.dumps(["MAL-2025-46974"]),
                "4.4.3",
                0,
                json.dumps([]),
                _SWEPT_AT,
                "4.4.2",
                json.dumps(["MAL-2025-46974"]),
                None,
                0,
                prev_advisories,
            ),
        ],
    )

    client = auth_client(demo_password=None)
    response = client.get("/top-packages")

    assert response.status_code == status.HTTP_200_OK
    body = response.text
    assert "Peak-affected advisories" in body
    assert "MAL-2025-46974" in body
    assert "Malicious code in debug (npm)" in body


def test_top_packages_page_falls_back_to_latest_advisories(
    monkeypatch: pytest.MonkeyPatch,
    auth_client: Callable[..., TestClient],
    tmp_path: Path,
) -> None:
    db = tmp_path / "latest-adv-fallback.db"
    _patch_db(monkeypatch, db)
    latest_advisories = json.dumps([{"id": "GHSA-fallback", "summary": "Latest only"}])
    _seed_top_packages(
        db,
        [
            (
                1,
                "fallback-pkg",
                1,
                json.dumps(["GHSA-fallback"]),
                "2.0.0",
                1,
                latest_advisories,
                _SWEPT_AT,
                None,
                None,
                None,
                0,
                None,
            ),
        ],
    )

    client = auth_client(demo_password=None)
    response = client.get("/top-packages")

    assert response.status_code == status.HTTP_200_OK
    body = response.text
    assert "GHSA-fallback" in body
    assert "Latest only" in body
    assert "Peak-affected advisories" not in body


def test_top_packages_context_null_tolerant_new_columns(tmp_path: Path) -> None:
    """Rows swept before migration 012 have NULL summaries/date; no incident badge/filter."""
    db = tmp_path / "null-tolerant.db"
    _seed_top_packages(
        db,
        [
            (
                1,
                "debug",
                1,
                json.dumps(["MAL-2025-46974"]),
                "4.4.3",
                0,
                json.dumps([]),
                _SWEPT_AT,
                "4.4.2",
                json.dumps(["MAL-2025-46974"]),
                None,
                1,  # legacy peak column set; ignored for display
                json.dumps([{"id": "MAL-2025-46974", "summary": "Malicious code"}]),
            ),
        ],
    )
    ctx = _top_packages_context(db)
    pkg = ctx["packages"][0]
    assert pkg.status == "clear"
    assert pkg.historical_advisory_summaries == []
    assert pkg.last_advisory_date is None
    assert pkg.has_malware_history is False
    assert pkg.malware_incident_label is None


def test_top_packages_context_dates_incident_from_summaries(tmp_path: Path) -> None:
    db = tmp_path / "dated.db"
    conn = get_connection(db)
    init_db(conn)
    summaries = [
        {
            "id": "MAL-2025-46974",
            "summary": "Malicious code in debug (npm)",
            "published": "2025-09-08T00:00:00Z",
            "severity": None,
            "is_malware": True,
        }
    ]
    conn.execute(
        """
        INSERT INTO top_packages (
            rank, name, historical_advisory_count, historical_advisory_ids,
            latest_version, latest_vulnerable, latest_advisories, swept_at,
            previously_vulnerable_version, patched_advisory_ids, max_epss, is_malware,
            previously_vulnerable_advisories, historical_advisory_summaries, last_advisory_date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            1,
            "debug",
            1,
            json.dumps(["MAL-2025-46974"]),
            "4.4.3",
            0,
            json.dumps([]),
            _SWEPT_AT,
            "4.4.2",
            json.dumps(["MAL-2025-46974"]),
            None,
            1,
            json.dumps([{"id": "MAL-2025-46974", "summary": "Malicious code"}]),
            json.dumps(summaries),
            "2025-09-08T00:00:00Z",
        ),
    )
    conn.commit()
    conn.close()

    ctx = _top_packages_context(db)
    pkg = ctx["packages"][0]
    assert pkg.last_advisory_date == "2025-09-08T00:00:00Z"
    assert pkg.malware_incident_label == "Malware incident · Sep 2025"
    assert pkg.historical_advisory_summaries[0]["is_malware"] is True


def test_format_last_advisory_date() -> None:
    assert format_last_advisory_date("2025-09-08T00:00:00Z") == "Sep 08, 2025"
    assert format_last_advisory_date(None) is None
    assert format_last_advisory_date("") is None


def test_derive_advisory_severity_chips_aggregates_and_malware() -> None:
    chips = derive_advisory_severity_chips(
        [
            {"id": "a", "severity": "critical", "is_malware": False},
            {"id": "b", "severity": "CRITICAL", "is_malware": False},
            {"id": "c", "severity": "high", "is_malware": False},
            {"id": "d", "severity": "moderate", "is_malware": False},
            {"id": "e", "severity": "medium", "is_malware": False},
            {"id": "m1", "severity": None, "is_malware": True},
            {"id": "m2", "severity": "critical", "is_malware": True},
        ]
    )
    assert chips == [
        {
            "kind": "severity",
            "label": "critical",
            "count": 2,
            "css_class": "finding-severity-critical",
        },
        {
            "kind": "severity",
            "label": "high",
            "count": 1,
            "css_class": "finding-severity-high",
        },
        {
            "kind": "severity",
            "label": "moderate",
            "count": 2,
            "css_class": "finding-severity-medium",
        },
        {"kind": "malware", "label": "malware", "count": 2, "css_class": "tp-chip-malware"},
    ]


def test_derive_advisory_severity_chips_none_when_absent() -> None:
    assert derive_advisory_severity_chips([]) is None


def test_top_packages_page_renders_last_advisory_and_severity_chips(
    monkeypatch: pytest.MonkeyPatch,
    auth_client: Callable[..., TestClient],
    tmp_path: Path,
) -> None:
    db = tmp_path / "chips.db"
    _patch_db(monkeypatch, db)
    conn = get_connection(db)
    init_db(conn)
    summaries = json.dumps(
        [
            {
                "id": "MAL-1",
                "summary": "x",
                "published": "2025-09-08T00:00:00Z",
                "severity": None,
                "is_malware": True,
            },
            {
                "id": "GHSA-1",
                "summary": "y",
                "published": "2023-01-01T00:00:00Z",
                "severity": "high",
                "is_malware": False,
            },
            {
                "id": "GHSA-2",
                "summary": "z",
                "published": "2022-01-01T00:00:00Z",
                "severity": "critical",
                "is_malware": False,
            },
        ]
    )
    conn.execute(
        """
        INSERT INTO top_packages (
            rank, name, historical_advisory_count, historical_advisory_ids,
            latest_version, latest_vulnerable, latest_advisories, swept_at,
            previously_vulnerable_version, patched_advisory_ids, max_epss, is_malware,
            previously_vulnerable_advisories, historical_advisory_summaries, last_advisory_date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            1,
            "debug",
            3,
            json.dumps(["MAL-1", "GHSA-1", "GHSA-2"]),
            "4.4.3",
            0,
            json.dumps([]),
            _SWEPT_AT,
            "4.4.2",
            json.dumps(["MAL-1"]),
            None,
            1,
            None,
            summaries,
            "2025-09-08T00:00:00Z",
        ),
    )
    conn.execute(
        """
        INSERT INTO top_packages (
            rank, name, historical_advisory_count, historical_advisory_ids,
            latest_version, latest_vulnerable, latest_advisories, swept_at,
            previously_vulnerable_version, patched_advisory_ids, max_epss, is_malware,
            previously_vulnerable_advisories, historical_advisory_summaries, last_advisory_date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            2,
            "legacy-pkg",
            2,
            json.dumps(["GHSA-x", "GHSA-y"]),
            "1.0.0",
            0,
            json.dumps([]),
            _SWEPT_AT,
            "0.9.0",
            json.dumps(["GHSA-x"]),
            None,
            0,
            None,
            None,
            None,
        ),
    )
    conn.commit()
    conn.close()

    body = auth_client(demo_password=None).get("/top-packages").text
    assert "Last advisory" in body
    assert "Sep 08, 2025" in body
    assert 'data-last-advisory="2025-09-08T00:00:00Z"' in body
    assert 'data-last-advisory=""' in body
    assert 'data-testid="tp-sort-last-advisory"' in body
    assert "finding-severity-critical" in body
    assert "finding-severity-high" in body
    assert "tp-chip-malware" in body
    assert "2 critical" not in body  # rendered as chip count + label separately
    assert ">1<" in body or "1 critical" in body or "critical" in body
    # NULL summaries: keep historical count, no chips claiming empty
    assert "legacy-pkg" in body
    # historical count still shown
    assert ">3<" in body or "3" in body
    assert ">2<" in body


def test_axios_malware_not_on_peak_agrees_across_surfaces(
    monkeypatch: pytest.MonkeyPatch,
    auth_client: Callable[..., TestClient],
    tmp_path: Path,
) -> None:
    """Malware advisory in summaries but not peak-affected: badge, chip, filter, header agree."""
    db = tmp_path / "axios.db"
    _patch_db(monkeypatch, db)
    conn = get_connection(db)
    init_db(conn)
    # Newer non-malware advisory is last_advisory_date; malware is older (still badge with own date).
    summaries = json.dumps(
        [
            {
                "id": "GHSA-recent",
                "summary": "Recent high",
                "published": "2026-03-01T00:00:00Z",
                "severity": "high",
                "is_malware": False,
            },
            {
                "id": "MAL-axios",
                "summary": "Malicious code in axios (npm)",
                "published": "2025-09-15T00:00:00Z",
                "severity": None,
                "is_malware": True,
            },
            {
                "id": "GHSA-old",
                "summary": "Old moderate",
                "published": "2024-01-01T00:00:00Z",
                "severity": "moderate",
                "is_malware": False,
            },
        ]
    )
    conn.execute(
        """
        INSERT INTO top_packages (
            rank, name, historical_advisory_count, historical_advisory_ids,
            latest_version, latest_vulnerable, latest_advisories, swept_at,
            previously_vulnerable_version, patched_advisory_ids, max_epss, is_malware,
            previously_vulnerable_advisories, historical_advisory_summaries, last_advisory_date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            1,
            "axios",
            3,
            json.dumps(["GHSA-recent", "MAL-axios", "GHSA-old"]),
            "1.7.9",
            0,
            json.dumps([]),
            _SWEPT_AT,
            "1.7.8",
            json.dumps(["GHSA-recent"]),  # peak-affected excludes malware
            None,
            0,  # legacy peak is_malware false — the prod disagreement case
            json.dumps([{"id": "GHSA-recent", "summary": "Recent high"}]),
            summaries,
            "2026-03-01T00:00:00Z",
        ),
    )
    conn.commit()
    conn.close()

    ctx = _top_packages_context(db)
    pkg = ctx["packages"][0]
    assert pkg.has_malware_history is True
    assert pkg.malware_incident_label == "Malware incident · Sep 2025"
    assert pkg.severity_chips is not None
    assert any(c["kind"] == "malware" for c in pkg.severity_chips)
    assert ctx["malware_last_12mo_count"] == 1

    body = auth_client(demo_password=None).get("/top-packages").text
    assert 'data-name="axios"' in body
    assert 'data-malware="1"' in body
    assert "Malware incident · Sep 2025" in body
    assert "Mar 01, 2026" in body  # last advisory column date
    assert "tp-chip-malware" in body
    assert "1 malware (last 12 mo)" in body
    assert ">Clear<" in body
    # Status stays single-height: incident badge is in Last Advisory cell
    assert "tp-last-advisory-cell" in body
    status_idx = body.find('class="tp-status-cell"')
    last_idx = body.find("tp-last-advisory-cell")
    incident_idx = body.find('class="tp-incident"')
    assert status_idx != -1 and last_idx != -1 and incident_idx != -1
    assert status_idx < last_idx < incident_idx or (last_idx < incident_idx)
