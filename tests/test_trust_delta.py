"""Tests for :func:`arguss.lenses.trust.fetch_delta` and ``trust-delta`` CLI."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from typer.testing import CliRunner

import arguss.cli as cli_mod
import arguss.lenses.trust as trust_mod
from arguss.core.cache import Cache, get_connection, init_db
from arguss.core.models import TrustFlag, TrustSnapshot
from arguss.lenses.trust import _is_cadence_anomaly, fetch_delta
from arguss.settings import Settings
from arguss.settings import settings as live_settings


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    conn = get_connection(tmp_path / "trust_delta.db")
    init_db(conn)
    return Cache(conn)


def _snap(
    package: str,
    version: str,
    *,
    logins: tuple[str, ...],
    published_at: datetime,
    weekly_downloads: int | None,
    subscore: int = 5,
) -> TrustSnapshot:
    return TrustSnapshot(
        package=package,
        version=version,
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
        maintainer_count=len(logins),
        maintainer_logins=logins,
        published_at=published_at,
        days_since_previous_publish=1,
        typosquat_distance=0,
        typosquat_nearest=package,
        weekly_downloads=weekly_downloads,
        subscore=subscore,
    )


def _fake_registry_cm(packument: dict[str, Any]) -> Any:
    inner = mock.MagicMock()
    inner.fetch_packument.return_value = packument
    cm = mock.MagicMock()
    cm.__enter__.return_value = inner
    cm.__exit__.return_value = None
    return cm


def test_delta_clean_no_flags(cache: Cache) -> None:
    """Same maintainers, no cadence flag, stable downloads → safe merge."""
    t0 = datetime(2020, 1, 1, tzinfo=UTC)
    t1 = t0 + timedelta(days=60)
    from_s = _snap("pkg", "1.0.0", logins=("a", "b"), published_at=t0, weekly_downloads=10_000)
    to_s = _snap("pkg", "2.0.0", logins=("a", "b"), published_at=t1, weekly_downloads=10_000)

    with (
        mock.patch.object(trust_mod, "fetch_snapshot", side_effect=[from_s, to_s]),
        mock.patch.object(trust_mod, "_is_cadence_anomaly", return_value=False),
        mock.patch.object(
            trust_mod,
            "TrustRegistryClient",
            new=mock.MagicMock(side_effect=lambda _c: _fake_registry_cm({})),
        ),
    ):
        d = fetch_delta(cache, "pkg", "1.0.0", "2.0.0")

    assert d.safe_to_auto_merge is True
    assert d.flags == ()
    assert d.maintainers_added == ()
    assert d.maintainers_removed == ()
    assert d.ownership_transferred is False


def test_delta_ownership_transfer_flag(cache: Cache) -> None:
    """>50% of original maintainers gone → OWNERSHIP_TRANSFER."""
    t0 = datetime(2020, 1, 1, tzinfo=UTC)
    t1 = t0 + timedelta(days=30)
    from_s = _snap("pkg", "1.0.0", logins=("a", "b"), published_at=t0, weekly_downloads=1000)
    to_s = _snap("pkg", "2.0.0", logins=("c", "d"), published_at=t1, weekly_downloads=1000)

    with (
        mock.patch.object(trust_mod, "fetch_snapshot", side_effect=[from_s, to_s]),
        mock.patch.object(trust_mod, "_is_cadence_anomaly", return_value=False),
        mock.patch.object(
            trust_mod,
            "TrustRegistryClient",
            new=mock.MagicMock(side_effect=lambda _c: _fake_registry_cm({})),
        ),
    ):
        d = fetch_delta(cache, "pkg", "1.0.0", "2.0.0")

    assert TrustFlag.OWNERSHIP_TRANSFER in d.flags
    assert d.safe_to_auto_merge is False
    assert d.ownership_transferred is True


def test_delta_new_maintainer_not_ownership(cache: Cache) -> None:
    """One maintainer added of five → NEW_MAINTAINER only."""
    t0 = datetime(2020, 1, 1, tzinfo=UTC)
    t1 = t0 + timedelta(days=30)
    base = ("a", "b", "c", "d", "e")
    from_s = _snap("pkg", "1.0.0", logins=base, published_at=t0, weekly_downloads=1000)
    to_s = _snap("pkg", "2.0.0", logins=base + ("f",), published_at=t1, weekly_downloads=1000)

    with (
        mock.patch.object(trust_mod, "fetch_snapshot", side_effect=[from_s, to_s]),
        mock.patch.object(trust_mod, "_is_cadence_anomaly", return_value=False),
        mock.patch.object(
            trust_mod,
            "TrustRegistryClient",
            new=mock.MagicMock(side_effect=lambda _c: _fake_registry_cm({})),
        ),
    ):
        d = fetch_delta(cache, "pkg", "1.0.0", "2.0.0")

    assert d.flags == (TrustFlag.NEW_MAINTAINER,)
    assert d.ownership_transferred is False
    assert d.maintainers_added == ("f",)
    assert d.maintainers_removed == ()


def test_cadence_anomaly_all_three_hold() -> None:
    """Short from→to gap vs ~30d historical median and enough history."""
    t0 = datetime(2000, 1, 1, tzinfo=UTC)
    times: dict[str, str] = {
        "created": "1999-01-01T00:00:00.000Z",
        "modified": "2005-01-01T00:00:00.000Z",
    }
    for i in range(12):
        key = f"1.0.{i}"
        times[key] = (t0 + timedelta(days=30 * i)).strftime("%Y-%m-%dT00:00:00.000Z")
    # compress last step: from 1.0.10 to 1.0.11 is 1 day only
    times["1.0.10"] = (t0 + timedelta(days=30 * 10)).strftime("%Y-%m-%dT00:00:00.000Z")
    times["1.0.11"] = (t0 + timedelta(days=30 * 10 + 1)).strftime("%Y-%m-%dT00:00:00.000Z")
    packument = {"time": times}
    assert _is_cadence_anomaly(packument, "1.0.10", "1.0.11") is True


def test_cadence_insufficient_history() -> None:
    """Fewer than 5 versions before ``to`` → never flag."""
    times = {
        "created": "1999-01-01T00:00:00.000Z",
        "modified": "2000-01-01T00:00:00.000Z",
        "1.0.0": "2000-01-01T00:00:00.000Z",
        "1.0.1": "2000-01-02T00:00:00.000Z",
        "1.0.2": "2000-01-03T00:00:00.000Z",
        "1.0.3": "2000-01-04T00:00:00.000Z",
    }
    assert _is_cadence_anomaly({"time": times}, "1.0.2", "1.0.3") is False


def test_cadence_seven_day_floor() -> None:
    """Gap below ratio threshold but not under 7 days → no flag."""
    t0 = datetime(2000, 1, 1, tzinfo=UTC)
    times: dict[str, str] = {
        "created": "1999-01-01T00:00:00.000Z",
        "modified": "2005-01-01T00:00:00.000Z",
    }
    for i in range(12):
        times[f"1.0.{i}"] = (t0 + timedelta(days=30 * i)).strftime("%Y-%m-%dT00:00:00.000Z")
    times["1.0.10"] = (t0 + timedelta(days=30 * 10)).strftime("%Y-%m-%dT00:00:00.000Z")
    times["1.0.11"] = (t0 + timedelta(days=30 * 10 + 8)).strftime("%Y-%m-%dT00:00:00.000Z")
    assert _is_cadence_anomaly({"time": times}, "1.0.10", "1.0.11") is False


def test_cadence_ratio_blocks_short_weekly_cadence() -> None:
    """Median ~3d weekly cadence; 2d gap fails ratio check (< 0.3 * median)."""
    t0 = datetime(2000, 1, 1, tzinfo=UTC)
    times: dict[str, str] = {
        "created": "1999-01-01T00:00:00.000Z",
        "modified": "2005-01-01T00:00:00.000Z",
    }
    for i in range(12):
        times[f"1.0.{i}"] = (t0 + timedelta(days=3 * i)).strftime("%Y-%m-%dT00:00:00.000Z")
    times["1.0.10"] = (t0 + timedelta(days=3 * 10)).strftime("%Y-%m-%dT00:00:00.000Z")
    times["1.0.11"] = (t0 + timedelta(days=3 * 10 + 2)).strftime("%Y-%m-%dT00:00:00.000Z")
    assert _is_cadence_anomaly({"time": times}, "1.0.10", "1.0.11") is False


def test_download_collapse_flag(cache: Cache) -> None:
    """>50% drop triggers DOWNLOAD_COLLAPSE."""
    t0 = datetime(2020, 1, 1, tzinfo=UTC)
    t1 = t0 + timedelta(days=10)
    from_s = _snap("pkg", "1.0.0", logins=("a",), published_at=t0, weekly_downloads=1000)
    to_s = _snap("pkg", "2.0.0", logins=("a",), published_at=t1, weekly_downloads=400)

    with (
        mock.patch.object(trust_mod, "fetch_snapshot", side_effect=[from_s, to_s]),
        mock.patch.object(trust_mod, "_is_cadence_anomaly", return_value=False),
        mock.patch.object(
            trust_mod,
            "TrustRegistryClient",
            new=mock.MagicMock(side_effect=lambda _c: _fake_registry_cm({})),
        ),
    ):
        d = fetch_delta(cache, "pkg", "1.0.0", "2.0.0")

    assert TrustFlag.DOWNLOAD_COLLAPSE in d.flags
    assert d.weekly_downloads_change_pct == pytest.approx(-0.6)


def test_download_change_none_skips_collapse_flag(cache: Cache) -> None:
    """Missing downloads → no pct, no download flag."""
    t0 = datetime(2020, 1, 1, tzinfo=UTC)
    t1 = t0 + timedelta(days=10)
    from_s = _snap("pkg", "1.0.0", logins=("a", "b"), published_at=t0, weekly_downloads=None)
    to_s = _snap("pkg", "2.0.0", logins=("a", "b"), published_at=t1, weekly_downloads=100)

    with (
        mock.patch.object(trust_mod, "fetch_snapshot", side_effect=[from_s, to_s]),
        mock.patch.object(trust_mod, "_is_cadence_anomaly", return_value=False),
        mock.patch.object(
            trust_mod,
            "TrustRegistryClient",
            new=mock.MagicMock(side_effect=lambda _c: _fake_registry_cm({})),
        ),
    ):
        d = fetch_delta(cache, "pkg", "1.0.0", "2.0.0")

    assert d.weekly_downloads_change_pct is None
    assert TrustFlag.DOWNLOAD_COLLAPSE not in d.flags


def test_multiple_flags_sorted(cache: Cache) -> None:
    """NEW_MAINTAINER + CADENCE_ANOMALY → sorted by enum value."""
    t0 = datetime(2020, 1, 1, tzinfo=UTC)
    t1 = t0 + timedelta(days=1)
    from_s = _snap("pkg", "1.0.0", logins=("a", "b"), published_at=t0, weekly_downloads=1000)
    to_s = _snap("pkg", "2.0.0", logins=("a", "b", "c"), published_at=t1, weekly_downloads=1000)

    with (
        mock.patch.object(trust_mod, "fetch_snapshot", side_effect=[from_s, to_s]),
        mock.patch.object(trust_mod, "_is_cadence_anomaly", return_value=True),
        mock.patch.object(
            trust_mod,
            "TrustRegistryClient",
            new=mock.MagicMock(side_effect=lambda _c: _fake_registry_cm({})),
        ),
    ):
        d = fetch_delta(cache, "pkg", "1.0.0", "2.0.0")

    assert d.flags == (TrustFlag.CADENCE_ANOMALY, TrustFlag.NEW_MAINTAINER)


def test_maintainers_sorted_in_deltas(cache: Cache) -> None:
    """added/removed tuples are alphabetically sorted."""
    t0 = datetime(2020, 1, 1, tzinfo=UTC)
    t1 = t0 + timedelta(days=10)
    from_s = _snap("pkg", "1.0.0", logins=("zebra", "alpha"), published_at=t0, weekly_downloads=100)
    to_s = _snap("pkg", "2.0.0", logins=("mike", "alpha"), published_at=t1, weekly_downloads=100)

    with (
        mock.patch.object(trust_mod, "fetch_snapshot", side_effect=[from_s, to_s]),
        mock.patch.object(trust_mod, "_is_cadence_anomaly", return_value=False),
        mock.patch.object(
            trust_mod,
            "TrustRegistryClient",
            new=mock.MagicMock(side_effect=lambda _c: _fake_registry_cm({})),
        ),
    ):
        d = fetch_delta(cache, "pkg", "1.0.0", "2.0.0")

    assert d.maintainers_added == ("mike",)
    assert d.maintainers_removed == ("zebra",)


def test_cli_trust_delta_success_and_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "cli_delta.db"
    monkeypatch.setattr(live_settings, "db_path", db)
    monkeypatch.setattr(Settings, "db_path", db)

    from arguss.core.models import TrustDelta

    fake = TrustDelta(
        package="x",
        from_version="1.0.0",
        to_version="2.0.0",
        maintainers_added=(),
        maintainers_removed=(),
        ownership_transferred=False,
        days_between_publishes=10,
        publish_cadence_anomaly=False,
        weekly_downloads_change_pct=0.0,
        flags=(),
        safe_to_auto_merge=True,
    )
    runner = CliRunner()
    with mock.patch.object(cli_mod, "fetch_delta", return_value=fake):
        ok = runner.invoke(cli_mod.app, ["trust-delta", "x", "1.0.0", "2.0.0"])
    assert ok.exit_code == 0
    body = json.loads(ok.stdout)
    assert body["safe_to_auto_merge"] is True

    from arguss.lenses._trust_client import TrustClientError

    with mock.patch.object(
        cli_mod,
        "fetch_delta",
        side_effect=TrustClientError("npm registry: missing 'x'"),
    ):
        bad = runner.invoke(cli_mod.app, ["trust-delta", "x", "1.0.0", "2.0.0"])
    assert bad.exit_code == 1


@pytest.mark.integration
def test_integration_lodash_delta_real_npm(tmp_path: Path) -> None:
    """Real registry: lodash patch delta has coherent structure."""
    conn = get_connection(tmp_path / "int_delta.db")
    init_db(conn)
    c = Cache(conn)
    try:
        d = fetch_delta(c, "lodash", "4.17.20", "4.17.21")
    finally:
        conn.close()

    assert d.package == "lodash"
    assert d.from_version == "4.17.20"
    assert d.to_version == "4.17.21"
    assert isinstance(d.days_between_publishes, int)
    assert isinstance(d.safe_to_auto_merge, bool)
    assert isinstance(d.flags, tuple)
