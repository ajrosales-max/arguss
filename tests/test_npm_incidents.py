"""Tests for curated npm incident loading and join rules."""

from __future__ import annotations

import json
from pathlib import Path

from arguss.core.cache import get_connection, init_db
from arguss.data.npm_incidents import (
    load_npm_incidents,
    match_package_to_incidents,
)
from arguss.web.dashboard import _top_packages_context

_SWEPT_AT = "2026-06-01T12:00:00Z"


def _write_incidents(path: Path, incidents: list[dict]) -> Path:
    path.write_text(json.dumps(incidents), encoding="utf-8")
    return path


def test_load_npm_incidents_parses_bundled_catalog() -> None:
    incidents = load_npm_incidents()
    assert len(incidents) >= 1
    assert all(i.incident_id and i.name and i.packages for i in incidents)


def test_match_requires_package_list_and_date_window(tmp_path: Path) -> None:
    catalog = load_npm_incidents(
        _write_incidents(
            tmp_path / "incidents.json",
            [
                {
                    "incident_id": "wave",
                    "name": "Test wave",
                    "date_range": ["2025-09-01", "2025-09-30"],
                    "packages": ["debug", "chalk"],
                    "description": "test",
                }
            ],
        )
    )
    in_window = [
        {
            "id": "MAL-1",
            "published": "2025-09-08T14:26:51Z",
            "is_malware": True,
        }
    ]
    outside = [
        {
            "id": "MAL-2",
            "published": "2025-07-21T06:24:05Z",
            "is_malware": True,
        }
    ]
    assert len(match_package_to_incidents("debug", in_window, catalog)) == 1
    # Package listed but advisory outside window → no match
    assert match_package_to_incidents("debug", outside, catalog) == []
    # Advisory in window but package not listed → no match
    assert match_package_to_incidents("axios", in_window, catalog) == []


def test_top_packages_context_joins_incident_and_header_count(tmp_path: Path) -> None:
    incidents_path = _write_incidents(
        tmp_path / "incidents.json",
        [
            {
                "incident_id": "wave",
                "name": "Test wave",
                "date_range": ["2025-09-01", "2025-09-30"],
                "packages": ["debug", "chalk"],
                "description": "test",
            }
        ],
    )
    db = tmp_path / "join.db"
    conn = get_connection(db)
    init_db(conn)
    for rank, name, published, listed_peak in (
        (1, "debug", "2025-09-08T14:26:51Z", 1),
        (2, "chalk", "2025-09-08T17:11:19Z", 1),
        (3, "alone", "2025-09-08T12:00:00Z", 0),  # malware date but not in list
    ):
        summaries = json.dumps(
            [
                {
                    "id": f"MAL-{name}",
                    "summary": "x",
                    "published": published,
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
                rank,
                name,
                1,
                json.dumps([f"MAL-{name}"]),
                "1.0.0",
                0,
                json.dumps([]),
                _SWEPT_AT,
                "0.9.0",
                json.dumps([f"MAL-{name}"]),
                None,
                listed_peak,
                None,
                summaries,
                published,
            ),
        )
    conn.commit()
    conn.close()

    ctx = _top_packages_context(db, incidents_path=incidents_path)
    by_name = {p.name: p for p in ctx["packages"]}
    assert by_name["debug"].linked_incident_id == "wave"
    assert by_name["debug"].linked_incident_chip == "Test wave · 2 packages"
    assert by_name["chalk"].linked_incident_chip == "Test wave · 2 packages"
    assert by_name["alone"].linked_incident_id is None
    assert by_name["alone"].linked_incident_chip is None
    assert by_name["alone"].malware_incident_label == "Malware incident · Sep 2025"
    assert ctx["malware_incident_count"] == 1


def test_top_packages_context_zero_incidents_matches_step2_shape(tmp_path: Path) -> None:
    """Empty curated catalog: no chips, no incident header count (Step 2 output)."""
    empty = _write_incidents(tmp_path / "empty.json", [])
    db = tmp_path / "zero.db"
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
            "2025-09-08T00:00:00Z",
        ),
    )
    conn.commit()
    conn.close()

    ctx = _top_packages_context(db, incidents_path=empty)
    pkg = ctx["packages"][0]
    assert pkg.linked_incident_id is None
    assert pkg.linked_incident_chip is None
    assert pkg.malware_incident_label == "Malware incident · Sep 2025"
    assert pkg.has_malware_history is True
    assert ctx["malware_incident_count"] is None
