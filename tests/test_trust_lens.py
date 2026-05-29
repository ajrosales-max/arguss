"""Unit tests for :class:`arguss.lenses.trust.TrustLens` aggregation."""

from __future__ import annotations

import logging
from pathlib import Path
from unittest import mock

import pytest

import arguss.lenses.trust as trust_mod
from arguss.core.cache import Cache, get_connection, init_db
from arguss.core.models import Dependency, TrustSnapshot
from arguss.lenses._trust_client import TrustClientError
from arguss.lenses.trust import TrustLens


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    conn = get_connection(tmp_path / "trust_lens.db")
    init_db(conn)
    return Cache(conn)


def _snap(name: str, ver: str, subscore: int) -> TrustSnapshot:
    from datetime import UTC, datetime

    return TrustSnapshot(
        package=name,
        version=ver,
        captured_at=datetime.now(UTC),
        maintainer_count=1,
        maintainer_logins=("u",),
        published_at=datetime(2020, 1, 1, tzinfo=UTC),
        days_since_previous_publish=1,
        typosquat_distance=0,
        typosquat_nearest=name,
        weekly_downloads=1000,
        subscore=subscore,
    )


def test_trust_lens_empty_deps(cache: Cache) -> None:
    out = TrustLens(cache).scan([])
    assert out.score == 0.0
    assert out.findings == []


def test_trust_lens_single_dep_top_n_degenerate(cache: Cache) -> None:
    snap = _snap("a", "1.0.0", 42)
    with mock.patch.object(trust_mod, "fetch_snapshot", return_value=snap):
        out = TrustLens(cache).scan([Dependency(name="a", version="1.0.0", direct=True)])
    assert out.score == 42.0
    assert len(out.findings) == 1


def test_trust_lens_top_ten_mean(cache: Cache) -> None:
    deps = [Dependency(name=f"p{i}", version="1.0.0", direct=True) for i in range(20)]
    # subscores 1..20 descending top-10 mean = mean(20,19,...,11) = 15.5
    side = [_snap(f"p{i}", "1.0.0", i + 1) for i in range(20)]

    def _side_effect(_c, name: str, ver: str) -> TrustSnapshot:
        idx = int(name[1:])
        return side[idx]

    with mock.patch.object(trust_mod, "fetch_snapshot", side_effect=_side_effect):
        out = TrustLens(cache).scan(deps)
    assert out.score == 15.5


def test_trust_lens_skips_failed_dep(cache: Cache) -> None:
    deps = [
        Dependency(name="ok", version="1.0.0", direct=True),
        Dependency(name="bad", version="1.0.0", direct=True),
    ]

    def _side_effect(c, name: str, ver: str) -> TrustSnapshot:
        if name == "bad":
            raise TrustClientError("gone")
        return _snap(name, ver, 50)

    with mock.patch.object(trust_mod, "fetch_snapshot", side_effect=_side_effect):
        out = TrustLens(cache).scan(deps)
    assert out.score == 50.0
    assert len(out.findings) == 1


def test_trust_lens_all_fail_score_zero_and_log(
    cache: Cache, caplog: pytest.LogCaptureFixture
) -> None:
    deps = [Dependency(name="x", version="1.0.0", direct=True)]
    with (
        mock.patch.object(trust_mod, "fetch_snapshot", side_effect=TrustClientError("nope")),
        caplog.at_level(logging.WARNING),
    ):
        out = TrustLens(cache).scan(deps)
    assert out.score == 0.0
    assert out.findings == []
    assert any("trust lens:" in r for r in caplog.messages)


def test_trust_lens_direct_deps_only_excludes_transitive(cache: Cache) -> None:
    deps = [Dependency(name=f"p{i}", version="1.0.0", direct=(i < 5)) for i in range(10)]
    side = [_snap(f"p{i}", "1.0.0", (i + 1) * 10) for i in range(10)]

    def _side_effect(_c, name: str, ver: str) -> TrustSnapshot:
        idx = int(name[1:])
        return side[idx]

    with mock.patch.object(trust_mod, "fetch_snapshot", side_effect=_side_effect):
        out = TrustLens(cache).scan(deps)
    # Direct p0-p4 subscores 10,20,30,40,50 → mean 30
    assert out.score == 30.0
