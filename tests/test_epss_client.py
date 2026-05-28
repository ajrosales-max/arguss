"""Tests for the EPSS client (mocked httpx; no live network)."""

from __future__ import annotations

from unittest.mock import AsyncMock

import httpx
import pytest

from arguss.core.cache import Cache, get_connection, init_db
from arguss.lenses._epss_client import EpssData, fetch_epss_for_cves


@pytest.fixture
def cache() -> Cache:
    conn = get_connection(":memory:")
    init_db(conn)
    return Cache(conn)


def _epss_payload(cves: list[tuple[str, str, str]]) -> dict:
    return {
        "status": "OK",
        "status-code": 200,
        "data": [
            {"cve": cve, "epss": epss, "percentile": pct, "date": "2024-01-01"}
            for cve, epss, pct in cves
        ],
    }


@pytest.mark.asyncio
async def test_fetch_epss_for_cves_happy_path() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert "CVE-2021-44228" in request.url.params.get("cve", "")
        assert "CVE-2024-0001" in request.url.params.get("cve", "")
        return httpx.Response(
            200,
            json=_epss_payload(
                [
                    ("CVE-2021-44228", "0.97565", "0.99963"),
                    ("CVE-2024-0001", "0.00042", "0.12345"),
                ]
            ),
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_epss_for_cves(
            ["CVE-2021-44228", "CVE-2024-0001"],
            http_client=client,
        )

    assert set(result.keys()) == {"CVE-2021-44228", "CVE-2024-0001"}
    assert result["CVE-2021-44228"] == EpssData(
        cve_id="CVE-2021-44228",
        epss=0.97565,
        percentile=0.99963,
        date="2024-01-01",
    )
    assert result["CVE-2024-0001"].epss == pytest.approx(0.00042)


@pytest.mark.asyncio
async def test_fetch_epss_for_cves_chunks_large_lists() -> None:
    cve_ids = [f"CVE-2024-{i:05d}" for i in range(250)]
    request_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        param = request.url.params.get("cve", "")
        chunk_size = len(param.split(","))
        assert chunk_size <= 100
        rows = [(cve, "0.1", "0.5") for cve in param.split(",") if cve]
        return httpx.Response(200, json=_epss_payload(rows))

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_epss_for_cves(cve_ids, http_client=client)

    assert request_count == 3
    assert len(result) == 250


@pytest.mark.asyncio
async def test_fetch_epss_returns_empty_on_http_error() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_epss_for_cves(["CVE-2024-0001"], http_client=client)

    assert result == {}


@pytest.mark.asyncio
async def test_fetch_epss_returns_empty_on_timeout() -> None:
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.side_effect = httpx.ConnectTimeout("timed out")

    result = await fetch_epss_for_cves(["CVE-2024-0001"], http_client=client)
    assert result == {}


@pytest.mark.asyncio
async def test_fetch_epss_uses_cache(cache: Cache) -> None:
    call_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(
            200,
            json=_epss_payload([("CVE-2024-0001", "0.5", "0.9")]),
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        first = await fetch_epss_for_cves(["CVE-2024-0001"], cache=cache, http_client=client)
        second = await fetch_epss_for_cves(["CVE-2024-0001"], cache=cache, http_client=client)

    assert call_count == 1
    assert first == second
    assert first["CVE-2024-0001"].epss == 0.5


@pytest.mark.asyncio
async def test_fetch_epss_handles_missing_cves() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_epss_payload(
                [
                    ("CVE-2024-0001", "0.1", "0.2"),
                    ("CVE-2024-0002", "0.2", "0.3"),
                ]
            ),
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_epss_for_cves(
            ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-9999"],
            http_client=client,
        )

    assert set(result.keys()) == {"CVE-2024-0001", "CVE-2024-0002"}
