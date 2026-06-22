"""Tests for the top-1000 OSV sweep job."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from arguss.core.cache import get_connection, init_db
from arguss.jobs.top_1000_sweep import (
    _advisory_records_for_npm_package,
    highest_affected_version,
    run_sweep,
)
from arguss.lenses._osv_client import OsvError


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
    assert mock_osv.fetch_vuln.call_count == 3

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


def _npm_affected(
    name: str,
    *,
    ranges: list[dict] | None = None,
    versions: list[str] | None = None,
) -> dict:
    entry: dict = {"package": {"name": name, "ecosystem": "npm"}}
    if ranges is not None:
        entry["ranges"] = ranges
    if versions is not None:
        entry["versions"] = versions
    return entry


def test_highest_affected_version_fixed_range_filters_versions() -> None:
    records = [
        {
            "id": "GHSA-fixed",
            "affected": [
                _npm_affected(
                    "lodash",
                    ranges=[
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "4.0.0"},
                                {"fixed": "4.17.21"},
                            ],
                        }
                    ],
                    versions=["4.17.19", "4.17.20", "4.17.21"],
                )
            ],
        }
    ]

    version, advisory_ids = highest_affected_version(records, "4.17.21")

    assert version == "4.17.20"
    assert advisory_ids == ["GHSA-fixed"]


def test_highest_affected_version_last_affected_event() -> None:
    records = [
        {
            "id": "GHSA-last",
            "affected": [
                _npm_affected(
                    "lodash.trimend",
                    ranges=[
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "4.0.0"},
                                {"last_affected": "4.5.1"},
                            ],
                        }
                    ],
                )
            ],
        }
    ]

    version, advisory_ids = highest_affected_version(records, "4.17.21")

    assert version == "4.5.1"
    assert advisory_ids == ["GHSA-last"]


def test_highest_affected_version_skips_non_npm_and_other_package_names() -> None:
    records = [
        {
            "id": "GHSA-mixed",
            "affected": [
                {
                    "package": {"name": "lodash-rails", "ecosystem": "RubyGems"},
                    "ranges": [],
                    "versions": ["4.17.20"],
                },
                _npm_affected(
                    "lodash-es",
                    ranges=[{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
                    versions=["4.17.20"],
                ),
                _npm_affected(
                    "lodash",
                    ranges=[{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
                    versions=["4.17.19"],
                ),
            ],
        }
    ]

    scoped = _advisory_records_for_npm_package(records, "lodash")
    version, advisory_ids = highest_affected_version(scoped, "4.17.21")

    assert version == "4.17.19"
    assert advisory_ids == ["GHSA-mixed"]


def test_highest_affected_version_multiple_advisories_share_peak() -> None:
    records = [
        {
            "id": "GHSA-a",
            "affected": [
                _npm_affected(
                    "pkg",
                    ranges=[{"events": [{"introduced": "0"}, {"last_affected": "2.0.0"}]}],
                )
            ],
        },
        {
            "id": "GHSA-b",
            "affected": [
                _npm_affected(
                    "pkg",
                    ranges=[{"events": [{"introduced": "0"}, {"fixed": "2.1.0"}]}],
                    versions=["2.0.0"],
                )
            ],
        },
    ]

    version, advisory_ids = highest_affected_version(records, "3.0.0")

    assert version == "2.0.0"
    assert advisory_ids == ["GHSA-a", "GHSA-b"]


def test_highest_affected_version_without_latest_picks_global_max() -> None:
    records = [
        {
            "id": "GHSA-open",
            "affected": [
                _npm_affected(
                    "pkg",
                    ranges=[{"events": [{"introduced": "0"}, {"last_affected": "9.9.9"}]}],
                )
            ],
        }
    ]

    version, advisory_ids = highest_affected_version(records, None)

    assert version == "9.9.9"
    assert advisory_ids == ["GHSA-open"]


def test_highest_affected_version_skips_unparseable_versions() -> None:
    records = [
        {
            "id": "GHSA-bad",
            "affected": [
                _npm_affected(
                    "pkg",
                    ranges=[{"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
                    versions=["not-a-version", "1.9.9"],
                )
            ],
        }
    ]

    version, advisory_ids = highest_affected_version(records, "2.0.0")

    assert version == "1.9.9"
    assert advisory_ids == ["GHSA-bad"]


def test_run_sweep_fetches_historical_advisories(tmp_path: Path) -> None:
    db_path = tmp_path / "hist.db"
    mock_osv = MagicMock()
    mock_osv.query_batch_packages.return_value = {"only-pkg": ["GHSA-hist-1"]}
    mock_osv.fetch_vuln.return_value = {
        "id": "GHSA-hist-1",
        "affected": [
            _npm_affected(
                "only-pkg",
                ranges=[{"events": [{"introduced": "0"}, {"last_affected": "1.0.0"}]}],
            )
        ],
    }
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
    mock_osv.fetch_vuln.assert_called_once_with("GHSA-hist-1")


def test_run_sweep_continues_when_fetch_vuln_raises(tmp_path: Path) -> None:
    db_path = tmp_path / "failsoft.db"
    mock_osv = MagicMock()
    mock_osv.query_batch_packages.return_value = {
        "resilient-pkg": ["GHSA-hist-good", "GHSA-hist-bad"],
    }
    mock_osv.query_single.return_value = ["GHSA-latest-bad", "GHSA-latest-good"]
    mock_registry = MagicMock()
    mock_registry.fetch_packument.return_value = {"dist-tags": {"latest": "1.0.0"}}

    good_hist = {
        "id": "GHSA-hist-good",
        "affected": [
            _npm_affected(
                "resilient-pkg",
                ranges=[{"events": [{"introduced": "0"}, {"last_affected": "0.9.0"}]}],
            )
        ],
    }
    good_latest = {"id": "GHSA-latest-good", "summary": "resolved advisory"}

    def fetch_side_effect(vid: str) -> dict:
        if vid == "GHSA-hist-bad":
            raise OsvError("OSV API call failed for vuln GHSA-hist-bad")
        if vid == "GHSA-latest-bad":
            raise OsvError("OSV API call failed for vuln GHSA-latest-bad")
        if vid == "GHSA-hist-good":
            return good_hist
        if vid == "GHSA-latest-good":
            return good_latest
        raise AssertionError(f"unexpected vuln id: {vid}")

    mock_osv.fetch_vuln.side_effect = fetch_side_effect

    count = run_sweep(
        db_path,
        latest=True,
        throttle=0,
        ranked_packages=[(1, "resilient-pkg")],
        osv_client=mock_osv,
        registry_client=mock_registry,
    )

    assert count == 1

    conn = get_connection(db_path)
    init_db(conn)
    row = _row(conn, "resilient-pkg")
    conn.close()

    assert row["name"] == "resilient-pkg"
    assert row["latest_version"] == "1.0.0"
    assert row["latest_vulnerable"] == 1
    latest_advisories = json.loads(str(row["latest_advisories"]))
    assert len(latest_advisories) == 1
    assert latest_advisories[0]["id"] == "GHSA-latest-good"
