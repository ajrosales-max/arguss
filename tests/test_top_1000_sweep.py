"""Tests for the top-1000 OSV sweep job."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from arguss.core.cache import get_connection, init_db
from arguss.jobs.top_1000_sweep import run_sweep


def _row(conn, name: str) -> dict[str, object]:
    row = conn.execute("SELECT * FROM top_packages WHERE name = ?", (name,)).fetchone()
    assert row is not None
    return dict(row)


def test_run_sweep_writes_rows_with_latest(tmp_path: Path) -> None:
    db_path = tmp_path / "sweep.db"
    mock_osv = MagicMock()
    mock_osv.query_batch_packages.return_value = {
        "alpha-pkg": ["GHSA-hist-1", "GHSA-hist-2"],
        "beta-pkg": [],
    }
    mock_osv.query_single.side_effect = [["GHSA-latest-1"], []]
    mock_osv.fetch_vuln.return_value = {"id": "GHSA-latest-1", "summary": "test"}

    mock_registry = MagicMock()
    mock_registry.fetch_packument.side_effect = [
        {"dist-tags": {"latest": "1.2.3"}},
        {"dist-tags": {"latest": "4.5.6"}},
    ]

    count = run_sweep(
        db_path,
        latest=True,
        throttle=0,
        ranked_packages=[(1, "alpha-pkg"), (2, "beta-pkg")],
        osv_client=mock_osv,
        registry_client=mock_registry,
    )

    assert count == 2
    mock_osv.query_batch_packages.assert_called_once_with(["alpha-pkg", "beta-pkg"])
    assert mock_osv.query_single.call_count == 2
    assert mock_registry.fetch_packument.call_count == 2

    conn = get_connection(db_path)
    init_db(conn)
    alpha = _row(conn, "alpha-pkg")
    beta = _row(conn, "beta-pkg")
    conn.close()

    assert alpha["rank"] == 1
    assert alpha["historical_advisory_count"] == 2
    assert json.loads(str(alpha["historical_advisory_ids"])) == ["GHSA-hist-1", "GHSA-hist-2"]
    assert alpha["latest_version"] == "1.2.3"
    assert alpha["latest_vulnerable"] == 1
    assert json.loads(str(alpha["latest_advisories"]))[0]["id"] == "GHSA-latest-1"
    assert alpha["swept_at"]

    assert beta["rank"] == 2
    assert beta["historical_advisory_count"] == 0
    assert json.loads(str(beta["historical_advisory_ids"])) == []
    assert beta["latest_version"] == "4.5.6"
    assert beta["latest_vulnerable"] == 0
    assert json.loads(str(beta["latest_advisories"])) == []


def test_run_sweep_latest_false_skips_pass_two(tmp_path: Path) -> None:
    db_path = tmp_path / "sweep.db"
    mock_osv = MagicMock()
    mock_osv.query_batch_packages.return_value = {"only-pkg": ["CVE-2024-0001"]}
    mock_registry = MagicMock()

    count = run_sweep(
        db_path,
        latest=False,
        throttle=0,
        ranked_packages=[(1, "only-pkg")],
        osv_client=mock_osv,
        registry_client=mock_registry,
    )

    assert count == 1
    mock_osv.query_single.assert_not_called()
    mock_registry.fetch_packument.assert_not_called()

    conn = get_connection(db_path)
    init_db(conn)
    row = _row(conn, "only-pkg")
    conn.close()

    assert row["historical_advisory_count"] == 1
    assert json.loads(str(row["historical_advisory_ids"])) == ["CVE-2024-0001"]
    assert row["latest_version"] is None
    assert row["latest_vulnerable"] is None
    assert row["latest_advisories"] is None
