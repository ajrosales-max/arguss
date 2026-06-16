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


def _deps_n(n: int) -> list[Dependency]:
    return [
        Dependency(name=f"pkg-{i}", version="1.0.0", ecosystem="npm", direct=True) for i in range(n)
    ]


def _batch_handler_chunked(
    chunk_sizes: list[int],
    *,
    fail_chunk_index: int | None = None,
) -> tuple[Callable[[httpx.Request], httpx.Response], list[int]]:
    """Return handler that records query counts per POST and optional failure on chunk N (1-based)."""
    post_sizes: list[int] = []
    chunk_num = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal chunk_num
        if "querybatch" not in str(request.url):
            return httpx.Response(404)
        body = json.loads(request.content.decode() if request.content else "{}")
        n = len(body["queries"])
        post_sizes.append(n)
        chunk_num += 1
        if fail_chunk_index is not None and chunk_num == fail_chunk_index:
            return httpx.Response(500)
        return httpx.Response(200, json={"results": [{"vulns": []} for _ in range(n)]})

    return handler, post_sizes


def test_query_batch_chunks_correctly(cache: Cache) -> None:
    handler, sizes = _batch_handler_chunked([500, 500, 500])
    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    client.query_batch(_deps_n(1500))
    assert sizes == [500, 500, 500]


def test_query_batch_chunk_boundary_uneven(cache: Cache) -> None:
    handler, sizes = _batch_handler_chunked([500, 500, 276])
    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    result = client.query_batch(_deps_n(1276))
    assert sizes == [500, 500, 276]
    assert len(result) == 1276
    assert all(result[f"pkg-{i}@1.0.0"] == [] for i in range(1276))


def test_query_batch_under_chunk_size_single_request(cache: Cache) -> None:
    handler, sizes = _batch_handler_chunked([100])
    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    client.query_batch(_deps_n(100))
    assert sizes == [100]


def test_query_batch_failure_on_any_chunk_raises(cache: Cache) -> None:
    handler, _sizes = _batch_handler_chunked([500, 500, 500], fail_chunk_index=2)
    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    with pytest.raises(OsvError, match=r"deps \[500:1000\]"):
        client.query_batch(_deps_n(1500))


def test_query_batch_no_partial_cache_on_failure(cache: Cache, tmp_path: Path) -> None:
    """If a later chunk fails, the batch ID map must not be cached."""
    handler, _sizes = _batch_handler_chunked([500, 500, 500], fail_chunk_index=2)
    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    deps = _deps_n(1500)
    seen: dict[tuple[str, str, str], Dependency] = {}
    for d in deps:
        seen[(d.ecosystem, d.name, d.version)] = d
    batch_key = f"batch:{osv_mod._hash_query_set(list(seen.values()))}"

    with pytest.raises(OsvError):
        client.query_batch(deps)

    assert cache.get_api_response("osv", batch_key) is None


def test_query_batch_packages_returns_ids_without_version(cache: Cache) -> None:
    seen_queries: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if "querybatch" in str(request.url):
            body = json.loads(request.content.decode() if request.content else "{}")
            seen_queries.extend(body["queries"])
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"vulns": [{"id": "GHSA-hist"}]},
                        {"vulns": []},
                    ]
                },
            )
        return httpx.Response(404)

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    result = client.query_batch_packages(["lodash", "safe-pkg"])
    assert result == {"lodash": ["GHSA-hist"], "safe-pkg": []}
    assert all("version" not in q for q in seen_queries)
    assert seen_queries[0]["package"] == {"ecosystem": "npm", "name": "lodash"}


def test_query_batch_packages_empty_input(cache: Cache) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail("Should not make HTTP calls for empty input")

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    assert client.query_batch_packages([]) == {}


def test_query_batch_packages_uses_cache(cache: Cache) -> None:
    batch_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal batch_calls
        if "querybatch" in str(request.url):
            batch_calls += 1
            return httpx.Response(200, json={"results": [{"vulns": []}]})
        return httpx.Response(404)

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    client.query_batch_packages(["once"])
    client.query_batch_packages(["once"])
    assert batch_calls == 1


def test_query_batch_packages_paginates_next_page_token(cache: Cache) -> None:
    post_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal post_calls
        if "querybatch" not in str(request.url):
            return httpx.Response(404)
        post_calls += 1
        body = json.loads(request.content.decode() if request.content else "{}")
        queries = body["queries"]
        if post_calls == 1:
            assert len(queries) == 1
            assert "page_token" not in queries[0]
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "vulns": [{"id": "GHSA-page1-a"}, {"id": "GHSA-page1-b"}],
                            "next_page_token": "token-abc",
                        }
                    ]
                },
            )
        assert post_calls == 2
        assert len(queries) == 1
        assert queries[0].get("page_token") == "token-abc"
        return httpx.Response(
            200,
            json={"results": [{"vulns": [{"id": "GHSA-page2-c"}]}]},
        )

    client = OsvClient(cache=cache, http_client=_mock_transport(handler))
    result = client.query_batch_packages(["busy-pkg"])
    assert result == {"busy-pkg": ["GHSA-page1-a", "GHSA-page1-b", "GHSA-page2-c"]}
    assert post_calls == 2
