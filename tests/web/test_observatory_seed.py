"""Tests for Observatory seed loader."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from arguss.web.observatory_seed import load_observatory_seed


def test_load_default_seed_aggregates_successes_only() -> None:
    data = load_observatory_seed()
    assert data.total_projects == data.stats.projects
    assert data.stats.projects >= 1
    assert data.stats.total_crit >= 1
    assert data.last_refreshed
    ok = [s for s in data.scans if s.error is None]
    assert data.stats.projects == len(ok)
    assert data.stats.total_crit == sum(s.crit_count for s in ok)


def test_load_seed_keeps_transient_error_row(tmp_path: Path) -> None:
    seed = {
        "version": 1,
        "generated_at": "2026-06-01T12:00:00+00:00",
        "last_refreshed": "2026-06-01T12:00:00+00:00",
        "total_projects": 99,
        "scans": [
            {
                "name": "axios",
                "owner": "axios",
                "repo": "axios",
                "ref": "main",
                "scanned_at": "2026-06-01T12:01:00+00:00",
                "crit_count": 2,
                "high_count": 3,
                "med_count": 1,
                "low_count": 0,
                "total_findings": 6,
                "kev_count": 0,
                "auto_fix_count": 1,
                "review_count": 1,
                "decline_count": 0,
                "scan_hash": "abc123",
                "error": None,
            },
            {
                "name": "eslint",
                "owner": "eslint",
                "repo": "eslint",
                "ref": "main",
                "scanned_at": None,
                "crit_count": 0,
                "high_count": 0,
                "med_count": 0,
                "low_count": 0,
                "total_findings": 0,
                "kev_count": 0,
                "auto_fix_count": 0,
                "review_count": 0,
                "decline_count": 0,
                "scan_hash": None,
                "error": "GitHubFetchError: timed out fetching tree",
            },
        ],
        "stats": {
            "projects": 99,
            "total_crit": 99,
            "total_kev": 99,
            "total_auto": 99,
        },
    }
    path = tmp_path / "observatory-seed.json"
    path.write_text(json.dumps(seed), encoding="utf-8")

    data = load_observatory_seed(path)

    assert len(data.scans) == 2
    assert data.scans[1].error is not None
    assert data.total_projects == 1
    assert data.stats.projects == 1
    assert data.stats.total_crit == 2
    assert data.stats.total_auto == 1
    assert data.last_refreshed == "Jun 01, 2026"


def test_load_seed_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_observatory_seed(tmp_path / "missing.json")
