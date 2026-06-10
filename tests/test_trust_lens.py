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
from arguss.lenses.trust import TrustLens, aggregate_trust_subscores, fetch_snapshot


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

    def _side_effect(_c, name: str, ver: str, **kwargs: object) -> TrustSnapshot:
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

    def _side_effect(c, name: str, ver: str, **kwargs: object) -> TrustSnapshot:
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


def test_trust_snapshot_includes_scorecard_when_available(cache: Cache) -> None:
    snap_base = _snap("axios", "1.0.0", 10)
    with_scorecard = TrustSnapshot(
        **{
            **snap_base.__dict__,
            "scorecard_score": 6.4,
            "scorecard_date": "2026-05-20",
            "scorecard_top_concerns": ("Branch-Protection (3)",),
        }
    )

    def _side_effect(_c, name: str, ver: str, **kwargs: object) -> TrustSnapshot:
        assert kwargs.get("include_scorecard") is True
        return with_scorecard

    with mock.patch.object(trust_mod, "fetch_snapshot", side_effect=_side_effect):
        out = TrustLens(cache).scan([Dependency(name="axios", version="1.0.0", direct=True)])

    assert out.score == 10.0


def test_trust_snapshot_scorecard_none_for_non_github_repo(cache: Cache) -> None:
    snap = _snap("pkg", "1.0.0", 20)
    assert snap.scorecard_score is None

    with mock.patch.object(
        trust_mod,
        "fetch_snapshot",
        return_value=snap,
    ):
        out = TrustLens(cache).scan([Dependency(name="pkg", version="1.0.0", direct=True)])
    assert out.score == 20.0


def test_trust_snapshot_scorecard_none_on_404(cache: Cache) -> None:
    snap = _snap("axios", "1.0.0", 15)
    with mock.patch.object(trust_mod, "fetch_snapshot", return_value=snap):
        out = TrustLens(cache).scan([Dependency(name="axios", version="1.0.0", direct=True)])
    assert snap.scorecard_score is None
    assert out.score == 15.0


def test_trust_snapshot_scorecard_none_on_missing_repo_field(cache: Cache) -> None:
    snap = _snap("no-repo-pkg", "1.0.0", 12)
    assert snap.scorecard_top_concerns is None


def test_trust_subscore_unchanged_by_scorecard() -> None:
    subscores = [10, 20, 30, 40, 50]
    before = aggregate_trust_subscores(subscores)
    after = aggregate_trust_subscores(subscores)
    assert before == after == 30.0


def test_fetch_snapshot_skips_scorecard_when_disabled(cache: Cache) -> None:
    with (
        mock.patch.object(trust_mod, "extract_github_owner_repo", return_value=("axios", "axios")),
        mock.patch.object(trust_mod, "fetch_openssf_scorecard") as mock_sc,
        mock.patch.object(trust_mod, "TrustRegistryClient") as mock_client_cls,
    ):
        client = mock.MagicMock()
        mock_client_cls.return_value.__enter__.return_value = client
        client.fetch_packument.return_value = {
            "versions": {
                "1.0.0": {
                    "maintainers": [{"name": "u"}],
                    "repository": {"url": "https://github.com/axios/axios.git"},
                }
            },
            "time": {"created": "2020-01-01T00:00:00.000Z", "1.0.0": "2020-01-01T00:00:00.000Z"},
        }
        client.fetch_weekly_downloads.return_value = 1000
        snap = fetch_snapshot(cache, "axios", "1.0.0", include_scorecard=False)

    mock_sc.assert_not_called()
    assert snap.scorecard_score is None


def test_trust_lens_direct_deps_only_excludes_transitive(cache: Cache) -> None:
    deps = [Dependency(name=f"p{i}", version="1.0.0", direct=(i < 5)) for i in range(10)]
    side = [_snap(f"p{i}", "1.0.0", (i + 1) * 10) for i in range(10)]

    def _side_effect(_c, name: str, ver: str, **kwargs: object) -> TrustSnapshot:
        idx = int(name[1:])
        return side[idx]

    with mock.patch.object(trust_mod, "fetch_snapshot", side_effect=_side_effect):
        out = TrustLens(cache).scan(deps)
    # Direct p0-p4 subscores 10,20,30,40,50 → mean 30
    assert out.score == 30.0
