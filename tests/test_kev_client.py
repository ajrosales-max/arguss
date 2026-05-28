"""Tests for the CISA KEV client (mocked httpx; no live network)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from arguss.core.cache import Cache, get_connection, init_db
from arguss.lenses._kev_client import KevEntry, fetch_kev_catalog


@pytest.fixture
def cache() -> Cache:
    conn = get_connection(":memory:")
    init_db(conn)
    return Cache(conn)


def _kev_feed_payload(vulns: list[dict]) -> dict:
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.05.27",
        "vulnerabilities": vulns,
    }


@pytest.mark.asyncio
async def test_fetch_kev_catalog_happy_path() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_kev_feed_payload(
                [
                    {
                        "cveID": "CVE-2021-44228",
                        "dateAdded": "2021-12-10",
                        "dueDate": "2021-12-24",
                        "knownRansomwareCampaignUse": "Known",
                    },
                    {
                        "cveID": "CVE-2024-0001",
                        "dateAdded": "2024-01-01",
                        "dueDate": "2024-02-01",
                        "knownRansomwareCampaignUse": "Unknown",
                    },
                ]
            ),
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_kev_catalog(http_client=client)

    assert set(result.keys()) == {"CVE-2021-44228", "CVE-2024-0001"}
    assert result["CVE-2021-44228"] == KevEntry(
        cve_id="CVE-2021-44228",
        date_added="2021-12-10",
        due_date="2021-12-24",
        known_ransomware=True,
    )
    assert result["CVE-2024-0001"].known_ransomware is False


@pytest.mark.asyncio
async def test_fetch_kev_catalog_caches_response(cache: Cache) -> None:
    call_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(
            200,
            json=_kev_feed_payload(
                [
                    {
                        "cveID": "CVE-2024-0001",
                        "dateAdded": "2024-01-01",
                        "dueDate": "2024-02-01",
                        "knownRansomwareCampaignUse": "Unknown",
                    }
                ]
            ),
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        first = await fetch_kev_catalog(cache=cache, http_client=client)
        second = await fetch_kev_catalog(cache=cache, http_client=client)

    assert call_count == 1
    assert first == second
    assert first["CVE-2024-0001"].cve_id == "CVE-2024-0001"


@pytest.mark.asyncio
async def test_fetch_kev_catalog_returns_empty_on_http_error() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_kev_catalog(http_client=client)

    assert result == {}


@pytest.mark.asyncio
async def test_fetch_kev_catalog_returns_empty_on_timeout() -> None:
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.side_effect = httpx.ConnectTimeout("timed out")

    result = await fetch_kev_catalog(http_client=client)
    assert result == {}


@pytest.mark.asyncio
async def test_fetch_kev_catalog_returns_empty_on_malformed_json() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_kev_catalog(http_client=client)

    assert result == {}


@pytest.mark.asyncio
async def test_fetch_kev_catalog_handles_missing_optional_fields() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_kev_feed_payload([{"cveID": "CVE-2024-9999"}]),
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_kev_catalog(http_client=client)

    entry = result["CVE-2024-9999"]
    assert entry.date_added is None
    assert entry.due_date is None
    assert entry.known_ransomware is False


@pytest.mark.asyncio
async def test_kev_known_ransomware_parsed_correctly() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_kev_feed_payload(
                [
                    {"cveID": "CVE-A", "knownRansomwareCampaignUse": "Known"},
                    {"cveID": "CVE-B", "knownRansomwareCampaignUse": "Unknown"},
                ]
            ),
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await fetch_kev_catalog(http_client=client)

    assert result["CVE-A"].known_ransomware is True
    assert result["CVE-B"].known_ransomware is False


@pytest.mark.asyncio
async def test_kev_catalog_cached_24h(cache: Cache) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_kev_feed_payload([{"cveID": "CVE-2024-0001"}]),
        )

    transport = httpx.MockTransport(handler)
    with patch.object(cache, "set_api_response") as mock_set:
        async with httpx.AsyncClient(transport=transport) as client:
            await fetch_kev_catalog(cache=cache, http_client=client)

    mock_set.assert_called_once()
    assert mock_set.call_args.kwargs["ttl_hours"] == 24
    assert mock_set.call_args.args[0] == "kev"
