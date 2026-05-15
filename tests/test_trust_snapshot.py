"""Unit tests for trust snapshot fetching + CLI.

Uses ``httpx.MockTransport`` for registry stubs (no live network in unit tests).
The integration test hits real npm and is excluded from the default run; see
``pyproject.toml`` ``addopts`` and ``pytest -m integration``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

import httpx
import pytest
from typer.testing import CliRunner

import arguss.cli as cli_mod
import arguss.lenses.trust as trust_mod
from arguss.core.cache import Cache, get_connection, init_db
from arguss.core.models import TrustSnapshot
from arguss.lenses._trust_client import (
    TrustClientError,
    TrustRegistryClient,
    _registry_path_segment,
)
from arguss.lenses.trust import fetch_snapshot
from arguss.settings import Settings
from arguss.settings import settings as live_settings


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    conn = get_connection(tmp_path / "trust_unit.db")
    init_db(conn)
    return Cache(conn)


def _mock_client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(handler),
        headers={"User-Agent": "arguss-test/trust-snapshot"},
    )


def _packument(
    package: str,
    version: str,
    *,
    maintainers: list[dict[str, str]],
    version_times: dict[str, str],
) -> dict[str, Any]:
    """Minimal npm packument JSON with one concrete version."""
    base_meta = {
        "created": "2009-01-01T00:00:00.000Z",
        "modified": "2025-01-01T00:00:00.000Z",
    }
    times = {**base_meta, **version_times}
    return {
        "name": package,
        "time": times,
        "versions": {
            version: {
                "name": package,
                "version": version,
                "maintainers": maintainers,
            }
        },
    }


@contextmanager
def _patched_trust_client(cache_arg: Cache, http_client: httpx.Client) -> Any:
    """Make ``fetch_snapshot`` use ``http_client`` against mock registry hosts."""

    def _factory(c: Cache) -> TrustRegistryClient:
        return TrustRegistryClient(
            c,
            http_client=http_client,
            registry_base="https://registry.test.npm",
            downloads_api_base="https://api.test.npm",
        )

    with mock.patch.object(trust_mod, "TrustRegistryClient", side_effect=_factory):
        yield


def _router_handler(
    *,
    packument_by_path_suffix: dict[str, dict[str, Any]],
    downloads_json: dict[str, Any] | None = None,
    downloads_status: int = 200,
) -> Callable[[httpx.Request], httpx.Response]:
    """Route GETs by URL path: packument vs downloads API."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/downloads/point/last-week/" in path:
            if downloads_status == 404:
                return httpx.Response(404)
            assert downloads_json is not None
            return httpx.Response(downloads_status, json=downloads_json)
        for suffix, body in packument_by_path_suffix.items():
            if path.endswith(suffix):
                return httpx.Response(200, json=body)
        return httpx.Response(404, json={"error": "not found"})

    return handler


def test_fetch_snapshot_populated_types_and_fields(cache: Cache) -> None:
    """Well-known shape: TrustSnapshot fields have expected types."""
    pkg, ver = "lodash", "1.0.0"
    body = _packument(
        pkg,
        ver,
        maintainers=[{"name": "a"}, {"name": "b"}],
        version_times={"0.0.1": "2010-01-01T00:00:00.000Z", ver: "2020-06-01T12:00:00.000Z"},
    )
    handler = _router_handler(
        packument_by_path_suffix={f"/{pkg}": body},
        downloads_json={"downloads": 50_000},
    )
    client = _mock_client(handler)
    with _patched_trust_client(cache, client):
        snap = fetch_snapshot(cache, pkg, ver)

    assert isinstance(snap, TrustSnapshot)
    assert snap.package == pkg
    assert snap.version == ver
    assert isinstance(snap.captured_at, datetime)
    assert snap.captured_at.tzinfo is not None
    assert snap.maintainer_count == 2
    assert snap.maintainer_logins == ("a", "b")
    assert isinstance(snap.published_at, datetime)
    assert snap.days_since_previous_publish == 3804  # 2010-01-01 -> 2020-06-01
    assert snap.weekly_downloads == 50_000
    assert isinstance(snap.subscore, int)
    assert 0 <= snap.subscore <= 100


def test_scoped_package_urls_encode_slash(cache: Cache) -> None:
    """Scoped names use ``%2F`` in the registry path segment (npm ``@scope/name``)."""
    pkg = "@types/node"
    ver = "20.0.0"
    assert _registry_path_segment(pkg) == "@types%2Fnode"

    body = _packument(
        pkg,
        ver,
        maintainers=[{"name": "types"}],
        version_times={ver: "2023-01-01T00:00:00.000Z"},
    )
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if "/downloads/point/last-week/" in request.url.path:
            return httpx.Response(200, json={"downloads": 9_000_000})
        return httpx.Response(200, json=body)

    client = _mock_client(handler)
    with _patched_trust_client(cache, client):
        fetch_snapshot(cache, pkg, ver)

    # httpx may normalize ``path``; full URL string should carry ``%2F`` for the scope slash.
    assert any("@types%2Fnode" in u for u in seen), seen


def test_subscore_sole_maintainer_contribution(cache: Cache) -> None:
    """Exactly one maintainer adds the sole-maintainer weight (30) when other risks off."""
    pkg = "zzz-arguss-sole-maint-test"
    ver = "1.0.0"
    body = _packument(
        pkg,
        ver,
        maintainers=[{"name": "onlyone"}],
        version_times={
            "0.0.1": "2008-01-01T00:00:00.000Z",
            ver: "2008-06-01T00:00:00.000Z",
        },
    )
    handler = _router_handler(
        packument_by_path_suffix={f"/{pkg}": body},
        downloads_json={"downloads": 50_000},
    )
    client = _mock_client(handler)
    with (
        mock.patch.object(trust_mod, "_TOP_1000_NPM", frozenset()),
        _patched_trust_client(cache, client),
    ):
        snap = fetch_snapshot(cache, pkg, ver)

    assert snap.maintainer_count == 1
    assert snap.typosquat_distance is None
    assert snap.subscore == 30


def test_typosquat_in_top_1000_self_match(cache: Cache) -> None:
    """Package present in bundled top-1000 → distance 0 and nearest is self."""
    pkg, ver = "lodash", "1.0.0"
    assert pkg in trust_mod._TOP_1000_NPM
    body = _packument(
        pkg,
        ver,
        maintainers=[{"name": "a"}, {"name": "b"}, {"name": "c"}],
        version_times={"0.0.1": "2010-01-01T00:00:00.000Z", ver: "2020-01-01T00:00:00.000Z"},
    )
    handler = _router_handler(
        packument_by_path_suffix={f"/{pkg}": body},
        downloads_json={"downloads": 1_000_000},
    )
    client = _mock_client(handler)
    with _patched_trust_client(cache, client):
        snap = fetch_snapshot(cache, pkg, ver)

    assert snap.typosquat_distance == 0
    assert snap.typosquat_nearest == pkg


def test_typosquat_distance_one_to_popular_name(cache: Cache) -> None:
    """Levenshtein distance 1 to a top-1000 name is detected with a nearest neighbor."""
    pkg = "exprss"
    ver = "1.0.0"
    assert pkg not in trust_mod._TOP_1000_NPM
    assert "express" in trust_mod._TOP_1000_NPM
    body = _packument(
        pkg,
        ver,
        maintainers=[{"name": "a"}, {"name": "b"}],
        version_times={"0.0.1": "2010-01-01T00:00:00.000Z", ver: "2020-01-01T00:00:00.000Z"},
    )
    handler = _router_handler(
        packument_by_path_suffix={f"/{pkg}": body},
        downloads_json={"downloads": 1_000_000},
    )
    client = _mock_client(handler)
    with _patched_trust_client(cache, client):
        snap = fetch_snapshot(cache, pkg, ver)

    assert snap.typosquat_distance == 1
    assert snap.typosquat_nearest is not None
    assert trust_mod._levenshtein(pkg, snap.typosquat_nearest) == 1


def test_typosquat_far_name_sanity_integer_distance(cache: Cache) -> None:
    """A name far from the popularity set still yields a concrete integer min distance."""
    pkg = "arguss-typosquat-far-zzzzzzzzzzzz"
    ver = "1.0.0"
    assert pkg not in trust_mod._TOP_1000_NPM
    body = _packument(
        pkg,
        ver,
        maintainers=[{"name": "a"}, {"name": "b"}],
        version_times={"0.0.1": "2010-01-01T00:00:00.000Z", ver: "2020-01-01T00:00:00.000Z"},
    )
    handler = _router_handler(
        packument_by_path_suffix={f"/{pkg}": body},
        downloads_json={"downloads": 1_000_000},
    )
    client = _mock_client(handler)
    with _patched_trust_client(cache, client):
        snap = fetch_snapshot(cache, pkg, ver)

    assert isinstance(snap.typosquat_distance, int)
    assert snap.typosquat_distance is not None
    assert snap.typosquat_distance > 2
    assert snap.typosquat_nearest is not None
    assert snap.typosquat_distance == trust_mod._levenshtein(pkg, snap.typosquat_nearest)


def test_weekly_downloads_404_yields_none_not_crash(cache: Cache) -> None:
    """404 on downloads API is cached as unavailable → ``weekly_downloads`` is None."""
    pkg, ver = "left-pad", "1.0.0"
    body = _packument(
        pkg,
        ver,
        maintainers=[{"name": "koz"}],
        version_times={ver: "2016-01-01T00:00:00.000Z"},
    )
    handler = _router_handler(
        packument_by_path_suffix={f"/{pkg}": body},
        downloads_status=404,
        downloads_json=None,
    )
    client = _mock_client(handler)
    with _patched_trust_client(cache, client):
        snap = fetch_snapshot(cache, pkg, ver)

    assert snap.weekly_downloads is None


def test_nonexistent_package_raises_trust_client_error(cache: Cache) -> None:
    """404 packument surfaces ``TrustClientError`` mentioning the package name."""
    pkg = "does-not-exist-package-xyz-trust-test"

    def handler(request: httpx.Request) -> httpx.Response:
        if "/downloads/" in request.url.path:
            return httpx.Response(200, json={"downloads": 0})
        return httpx.Response(404, json={"error": "not found"})

    client = _mock_client(handler)
    with _patched_trust_client(cache, client), pytest.raises(TrustClientError) as excinfo:
        fetch_snapshot(cache, pkg, "1.0.0")
    assert pkg in str(excinfo.value)


def test_second_fetch_uses_cache_no_extra_http(cache: Cache) -> None:
    """Within TTL, repeat ``fetch_snapshot`` does not hit the transport again."""
    pkg, ver = "cache-hit-pkg", "2.0.0"
    body = _packument(
        pkg,
        ver,
        maintainers=[{"name": "u1"}, {"name": "u2"}],
        version_times={"1.0.0": "2015-01-01T00:00:00.000Z", ver: "2016-01-01T00:00:00.000Z"},
    )
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if "/downloads/point/last-week/" in request.url.path:
            return httpx.Response(200, json={"downloads": 10_000})
        return httpx.Response(200, json=body)

    client = _mock_client(handler)
    with (
        mock.patch.object(trust_mod, "_TOP_1000_NPM", frozenset()),
        _patched_trust_client(cache, client),
    ):
        fetch_snapshot(cache, pkg, ver)
        assert calls["n"] == 2
        fetch_snapshot(cache, pkg, ver)
        assert calls["n"] == 2


def test_cli_trust_snapshot_json_success_and_error_exit_codes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CLI prints JSON and exits 0 on success; non-zero when ``fetch_snapshot`` fails."""
    db = tmp_path / "cli_trust.db"
    monkeypatch.setattr(live_settings, "db_path", db)
    monkeypatch.setattr(Settings, "db_path", db)

    runner = CliRunner()
    fake = TrustSnapshot(
        package="demo-pkg",
        version="9.9.9",
        captured_at=datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC),
        maintainer_count=2,
        maintainer_logins=("alice", "bob"),
        published_at=datetime(2020, 1, 1, 0, 0, 0, tzinfo=UTC),
        days_since_previous_publish=5,
        typosquat_distance=0,
        typosquat_nearest="demo-pkg",
        weekly_downloads=1234,
        subscore=0,
    )

    with mock.patch.object(cli_mod, "fetch_snapshot", return_value=fake):
        result = runner.invoke(cli_mod.app, ["trust-snapshot", "demo-pkg", "9.9.9"])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    assert parsed["package"] == "demo-pkg"
    assert parsed["version"] == "9.9.9"
    assert parsed["maintainer_logins"] == ["alice", "bob"]

    with mock.patch.object(
        cli_mod,
        "fetch_snapshot",
        side_effect=TrustClientError("npm registry: package not found: 'bad-pkg'"),
    ):
        err = runner.invoke(cli_mod.app, ["trust-snapshot", "bad-pkg", "1.0.0"])
    assert err.exit_code == 1
    assert "bad-pkg" in err.stdout or "bad-pkg" in str(err.output)


@pytest.mark.integration
def test_integration_lodash_real_npm_registry(tmp_path: Path) -> None:
    """End-to-end fetch of lodash@4.17.21 against the live npm registry."""
    conn = get_connection(tmp_path / "trust_integration.db")
    init_db(conn)
    cache = Cache(conn)
    try:
        snap = fetch_snapshot(cache, "lodash", "4.17.21")
    finally:
        conn.close()

    assert snap.package == "lodash"
    assert snap.version == "4.17.21"
    assert isinstance(snap.captured_at, datetime)
    assert isinstance(snap.published_at, datetime)
    assert snap.typosquat_distance == 0
    assert snap.typosquat_nearest == "lodash"
    assert snap.maintainer_count >= 1
    assert snap.weekly_downloads is None or snap.weekly_downloads >= 0
