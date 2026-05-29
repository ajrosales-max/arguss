"""Tests for the OpenSSF Scorecard client (mocked httpx; no live network)."""

from __future__ import annotations

import httpx
import pytest

from arguss.core.cache import Cache, get_connection, init_db
from arguss.lenses._scorecard_client import ScorecardCheck, ScorecardResult, fetch_scorecard


@pytest.fixture
def cache() -> Cache:
    conn = get_connection(":memory:")
    init_db(conn)
    return Cache(conn)


def _axios_payload() -> dict:
    return {
        "date": "2026-05-20",
        "repo": {"name": "github.com/axios/axios", "commit": "abc123"},
        "scorecard": {"version": "v5.0.0", "commit": "def456"},
        "score": 6.4,
        "checks": [
            {
                "name": "Binary-Artifacts",
                "score": 10,
                "reason": "no binaries found in the repo",
            },
            {
                "name": "Branch-Protection",
                "score": 3,
                "reason": "branch protection is not maximal",
            },
            {
                "name": "Pinned-Dependencies",
                "score": 2,
                "reason": "dependency not pinned",
            },
            {
                "name": "Inconclusive-Check",
                "score": -1,
                "reason": "not evaluated",
            },
        ],
    }


@pytest.mark.asyncio
async def test_fetch_scorecard_success() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/axios/axios")
        return httpx.Response(200, json=_axios_payload())

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_scorecard("axios", "axios", http_client=client)

    assert result is not None
    assert result.score == pytest.approx(6.4)
    assert result.date == "2026-05-20"
    assert len(result.checks) == 4


@pytest.mark.asyncio
async def test_fetch_scorecard_404_returns_none() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_scorecard("unknown", "pkg", http_client=client)

    assert result is None


@pytest.mark.asyncio
async def test_fetch_scorecard_timeout_returns_none() -> None:
    from unittest.mock import AsyncMock

    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.side_effect = httpx.ConnectTimeout("timed out")

    result = await fetch_scorecard("axios", "axios", http_client=client)
    assert result is None


@pytest.mark.asyncio
async def test_fetch_scorecard_malformed_returns_none() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"score": "not-a-number", "date": "2026-01-01"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_scorecard("axios", "axios", http_client=client)

    assert result is None


@pytest.mark.asyncio
async def test_fetch_scorecard_uses_cache(cache: Cache) -> None:
    call_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(200, json=_axios_payload())

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        first = await fetch_scorecard("axios", "axios", cache=cache, http_client=client)
        second = await fetch_scorecard("axios", "axios", cache=cache, http_client=client)

    assert call_count == 1
    assert first == second
    assert first is not None
    assert first.score == pytest.approx(6.4)


@pytest.mark.asyncio
async def test_fetch_scorecard_caches_404_briefly(cache: Cache) -> None:
    call_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        first = await fetch_scorecard("missing", "repo", cache=cache, http_client=client)
        second = await fetch_scorecard("missing", "repo", cache=cache, http_client=client)

    assert first is None
    assert second is None
    assert call_count == 1
    cached = cache.get_api_response("scorecard", "scorecard:missing/repo")
    assert cached == {"absent": True}


def test_top_concerns_excludes_inconclusive() -> None:
    result = ScorecardResult(
        score=5.0,
        date="2026-01-01",
        checks=(
            ScorecardCheck("Good", 10, ""),
            ScorecardCheck("Bad", 1, ""),
            ScorecardCheck("Unknown", -1, ""),
        ),
    )
    assert result.top_concerns(1) == ["Bad (1)"]


def test_top_concerns_returns_n_lowest() -> None:
    result = ScorecardResult(
        score=5.0,
        date="2026-01-01",
        checks=(
            ScorecardCheck("A", 8, ""),
            ScorecardCheck("B", 2, ""),
            ScorecardCheck("C", 5, ""),
            ScorecardCheck("D", 1, ""),
        ),
    )
    assert result.top_concerns(2) == ["D (1)", "B (2)"]
