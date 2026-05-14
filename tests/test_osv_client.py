"""Tests for the OSV client. Uses httpx MockTransport — no live network calls."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from arguss.core.cache import Cache, get_connection, init_db
from arguss.core.models import Dependency
from arguss.lenses import _osv_client as osv_mod
from arguss.lenses._osv_client import OsvClient, OsvError


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    conn = get_connection(tmp_path / "test.db")
    init_db(conn)
    return Cache(conn)


def _mock_transport(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_query_single_returns_vuln_ids(cache: Cache) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"vulns": [{"id": "GHSA-1111-2222-3333"}, {"id": "CVE-2024-0001"}]},
        )

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    ids = client.query_single("lodash", "4.17.20")
    assert ids == ["GHSA-1111-2222-3333", "CVE-2024-0001"]


def test_query_single_uses_cache(cache: Cache) -> None:
    """Second call with same args returns cached result without HTTP."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(200, json={"vulns": [{"id": "X"}]})

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    client.query_single("foo", "1.0.0")
    client.query_single("foo", "1.0.0")
    assert call_count == 1


def test_query_single_no_vulns(cache: Cache) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    assert client.query_single("clean", "1.0.0") == []


def test_query_single_raises_on_http_error(cache: Cache) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    with pytest.raises(OsvError):
        client.query_single("anything", "1.0.0")


def test_query_single_raises_on_invalid_json(cache: Cache) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json {")

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    with pytest.raises(OsvError, match="invalid JSON"):
        client.query_single("x", "1.0.0")


def test_query_single_raises_on_non_object_json(cache: Cache) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=["unexpected"])

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    with pytest.raises(OsvError, match="unexpected JSON root"):
        client.query_single("x", "1.0.0")


def test_fetch_vuln_returns_record(cache: Cache) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "GHSA-X", "summary": "fake CVE"})

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    record = client.fetch_vuln("GHSA-X")
    assert record["id"] == "GHSA-X"
    assert record["summary"] == "fake CVE"


def test_fetch_vuln_uses_seven_day_cache(cache: Cache) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"id": "GHSA-Y", "summary": "x"})

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    client.fetch_vuln("GHSA-Y")
    client.fetch_vuln("GHSA-Y")
    assert calls == 1


def test_fetch_vuln_raises_on_invalid_json(cache: Cache) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not-json")

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    with pytest.raises(OsvError, match="invalid JSON"):
        client.fetch_vuln("GHSA-Z")


def test_fetch_vuln_raises_on_non_object_json(cache: Cache) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[1, 2, 3])

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    with pytest.raises(OsvError, match="unexpected JSON root"):
        client.fetch_vuln("GHSA-Z")


def test_query_batch_returns_vulns_per_dep(cache: Cache) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "querybatch" in str(request.url):
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"vulns": [{"id": "GHSA-1"}]},
                        {"vulns": []},
                    ]
                },
            )
        if "/v1/vulns/GHSA-1" in str(request.url):
            return httpx.Response(200, json={"id": "GHSA-1", "summary": "test"})
        return httpx.Response(404)

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    deps = [
        Dependency(name="vulnerable", version="1.0.0", ecosystem="npm", direct=True),
        Dependency(name="safe", version="2.0.0", ecosystem="npm", direct=True),
    ]
    result = client.query_batch(deps)
    assert result["vulnerable@1.0.0"][0]["id"] == "GHSA-1"
    assert result["safe@2.0.0"] == []


def test_query_batch_empty_input(cache: Cache) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail("Should not make HTTP calls for empty input")

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    assert client.query_batch([]) == {}


def test_query_batch_dedupes_same_package_version(cache: Cache) -> None:
    """Same package@version appearing multiple times queries once."""
    queries_received: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if "querybatch" in str(request.url):
            body = json.loads(request.content.decode() if request.content else "{}")
            queries_received.append(len(body["queries"]))
            n = len(body["queries"])
            return httpx.Response(200, json={"results": [{"vulns": []} for _ in range(n)]})
        return httpx.Response(404)

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    deps = [
        Dependency(name="a", version="1.0.0", ecosystem="npm", direct=True),
        Dependency(
            name="a",
            version="1.0.0",
            ecosystem="npm",
            direct=False,
            path=["root", "x", "a"],
        ),
        Dependency(name="b", version="2.0.0", ecosystem="npm", direct=True),
    ]
    client.query_batch(deps)
    assert queries_received == [2]


def test_query_batch_uses_batch_cache(cache: Cache) -> None:
    batch_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal batch_calls
        if "querybatch" in str(request.url):
            batch_calls += 1
            return httpx.Response(200, json={"results": [{"vulns": []}]})
        return httpx.Response(404)

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    d = Dependency(name="only", version="1.0.0", ecosystem="npm", direct=True)
    client.query_batch([d])
    client.query_batch([d])
    assert batch_calls == 1


def test_query_batch_raises_on_invalid_json(cache: Cache) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "querybatch" in str(request.url):
            return httpx.Response(200, content=b"{not valid")
        return httpx.Response(404)

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    deps = [Dependency(name="x", version="1.0.0", ecosystem="npm", direct=True)]
    with pytest.raises(OsvError, match="invalid JSON"):
        client.query_batch(deps)


def test_query_batch_raises_on_result_count_mismatch(cache: Cache) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": [{"vulns": []}]})

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    deps = [
        Dependency(name="a", version="1.0.0", ecosystem="npm", direct=True),
        Dependency(name="b", version="2.0.0", ecosystem="npm", direct=True),
    ]
    with pytest.raises(OsvError, match="length mismatch"):
        client.query_batch(deps)


def test_query_batch_uses_longer_timeout_for_post(cache: Cache) -> None:
    """Batch POST is invoked with OSV_TIMEOUT_BATCH (15s read)."""
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if "querybatch" in str(request.url):
            return httpx.Response(200, json={"results": [{"vulns": []}]})
        return httpx.Response(404)

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    real_post = client._http.post

    def spy_post(*args: object, **kwargs: object) -> httpx.Response:
        if args and "querybatch" in str(args[0]):
            seen["timeout"] = kwargs.get("timeout")
        return real_post(*args, **kwargs)

    client._http.post = spy_post  # type: ignore[method-assign]

    client.query_batch([Dependency(name="x", version="1.0.0", ecosystem="npm", direct=True)])
    assert seen.get("timeout") == osv_mod.OSV_TIMEOUT_BATCH
