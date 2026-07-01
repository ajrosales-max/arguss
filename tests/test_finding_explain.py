"""Tests for per-finding dashboard Claude explanations."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

import httpx
import pytest
from anthropic import APIError
from fastapi import status
from fastapi.testclient import TestClient

import arguss.engine.explanation as explanation_mod
import arguss.explanations._client as client_mod
import arguss.web.dashboard as dashboard_mod
import arguss.web.results_context as results_context_mod
from arguss.api import create_app
from arguss.core.cache import Cache, get_connection, init_db
from arguss.settings import settings as live_settings

_FINDING_EXPLAIN_SOURCE = "finding_explain"
_FINDING_EXPLAIN_TTL_SECONDS = 86400


@pytest.fixture
def api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live_settings, "anthropic_api_key", "sk-ant-test-key")


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def _db(tmp_path: Path) -> Cache:
    conn = get_connection(tmp_path / "cache.db")
    init_db(conn)
    return Cache(conn)


def _scan_entry(
    *,
    finding_id: str = "finding-abc",
    advisory_id: str = "GHSA-explain-1",
) -> dict:
    return {
        "finding": {
            "finding_id": finding_id,
            "advisory_id": advisory_id,
            "title": f"{advisory_id}: example issue",
            "description": "Example vulnerability description for the prompt.",
            "cvss_score": 7.5,
            "dependency": {"name": "lodash", "version": "4.17.20"},
        },
        "candidate": {
            "package": "lodash",
            "from_version": "4.17.20",
            "to_version": "4.17.21",
            "fix_kind": "patch",
        },
        "verdict": {
            "tier": "review_required",
            "score": 55,
            "reasons": ["Patch within semver range"],
            "veto_signals": [],
        },
    }


def _cached_scan(*, entries: list[dict] | None = None) -> dict:
    return {"entries": entries if entries is not None else [_scan_entry()]}


def _mock_anthropic_client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    text: str | None = "Dashboard finding prose.",
    content: list | None = None,
    side_effect: BaseException | None = None,
) -> mock.MagicMock:
    mock_client = mock.MagicMock()
    if side_effect is not None:
        mock_client.messages.create.side_effect = side_effect
    else:
        if content is None:
            block = mock.MagicMock()
            block.text = text
            content = [block]
        mock_message = mock.MagicMock()
        mock_message.content = content
        mock_client.messages.create.return_value = mock_message

    monkeypatch.setattr(
        client_mod,
        "Anthropic",
        lambda **kwargs: mock_client,
    )
    return mock_client


def _post_finding_explain(
    client: TestClient,
    *,
    scan_hash: str = "abc123scan",
    finding_id: str = "finding-abc",
):
    return client.post(
        "/dashboard/finding-explain",
        data={"scan_hash": scan_hash, "finding_id": finding_id},
    )


def test_lookup_returns_matching_entry() -> None:
    entry = _scan_entry(finding_id="match-me")
    scan = _cached_scan(entries=[entry, _scan_entry(finding_id="other")])
    with mock.patch(
        "arguss.explanations.scan_cache.get_cached_scan_response",
        return_value=scan,
    ):
        found = results_context_mod.lookup_cached_entry_by_finding_id("hash1", "match-me")
    assert found is entry


def test_lookup_returns_none_when_scan_missing() -> None:
    with mock.patch(
        "arguss.explanations.scan_cache.get_cached_scan_response",
        return_value=None,
    ):
        assert results_context_mod.lookup_cached_entry_by_finding_id("hash1", "x") is None


def test_lookup_returns_none_when_entries_not_list() -> None:
    with mock.patch(
        "arguss.explanations.scan_cache.get_cached_scan_response",
        return_value={"entries": "not-a-list"},
    ):
        assert results_context_mod.lookup_cached_entry_by_finding_id("hash1", "x") is None


def test_lookup_returns_none_when_finding_id_blank() -> None:
    scan = _cached_scan()
    with mock.patch(
        "arguss.explanations.scan_cache.get_cached_scan_response",
        return_value=scan,
    ):
        assert results_context_mod.lookup_cached_entry_by_finding_id("hash1", "   ") is None


def test_lookup_returns_none_when_no_matching_finding() -> None:
    scan = _cached_scan(entries=[_scan_entry(finding_id="known-only")])
    with mock.patch(
        "arguss.explanations.scan_cache.get_cached_scan_response",
        return_value=scan,
    ):
        assert results_context_mod.lookup_cached_entry_by_finding_id("hash1", "missing") is None


def test_explain_finding_returns_prose_on_success(
    api_key: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prose = "This upgrade warrants review because trust signals are thin."
    _mock_anthropic_client(monkeypatch, text=prose)

    result = explanation_mod.explain_finding_verdict_to_human(_scan_entry())

    assert result == prose


def test_explain_finding_returns_none_on_api_error(
    api_key: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    err = APIError("rate limited", request=request, body=None)
    _mock_anthropic_client(monkeypatch, side_effect=err)

    assert explanation_mod.explain_finding_verdict_to_human(_scan_entry()) is None


def test_explain_finding_returns_none_when_response_empty(
    api_key: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_anthropic_client(monkeypatch, content=[])

    assert explanation_mod.explain_finding_verdict_to_human(_scan_entry()) is None


def test_explain_finding_prompt_includes_advisory_id(
    api_key: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_client = _mock_anthropic_client(monkeypatch)
    advisory_id = "GHSA-prompt-finding-42"
    entry = _scan_entry(advisory_id=advisory_id)

    explanation_mod.explain_finding_verdict_to_human(entry)

    _, kwargs = mock_client.messages.create.call_args
    user_content = kwargs["messages"][0]["content"]
    assert advisory_id in user_content
    assert "lodash" in user_content


def test_finding_explain_cache_miss_generates_caches_and_returns_prose(
    client: TestClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "db_path", tmp_path / "cache.db")
    scan_hash = "scanhash001"
    finding_id = "finding-abc"
    prose = "Generated explanation for the finding card."
    scan = _cached_scan(entries=[_scan_entry(finding_id=finding_id)])

    with (
        mock.patch(
            "arguss.explanations.scan_cache.get_cached_scan_response",
            return_value=scan,
        ),
        mock.patch.object(
            dashboard_mod,
            "explain_finding_verdict_to_human",
            return_value=prose,
        ) as mock_explain,
    ):
        response = _post_finding_explain(client, scan_hash=scan_hash, finding_id=finding_id)

    assert response.status_code == status.HTTP_200_OK
    assert prose in response.text
    assert "finding-explain-prose" in response.text
    mock_explain.assert_called_once()

    cache = _db(tmp_path)
    cached = cache.get_cached_text(_FINDING_EXPLAIN_SOURCE, f"{scan_hash}:{finding_id}")
    assert cached == prose

    row = cache.conn.execute(
        """
        SELECT response_json, source, expires_at FROM api_cache
        WHERE key = ? AND source = ?
        """,
        (f"{scan_hash}:{finding_id}", _FINDING_EXPLAIN_SOURCE),
    ).fetchone()
    assert row is not None
    assert row["source"] == _FINDING_EXPLAIN_SOURCE
    assert json.loads(row["response_json"])["text"] == prose
    expires_at = datetime.fromisoformat(row["expires_at"])
    assert expires_at > datetime.now(UTC) + timedelta(seconds=_FINDING_EXPLAIN_TTL_SECONDS - 120)


def test_finding_explain_cache_hit_skips_claude(
    client: TestClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "db_path", tmp_path / "cache.db")
    scan_hash = "cachedscan"
    finding_id = "finding-abc"
    cached_prose = "Previously cached explanation."
    cache = _db(tmp_path)
    cache.set_cached_text(
        _FINDING_EXPLAIN_SOURCE,
        f"{scan_hash}:{finding_id}",
        cached_prose,
        ttl_seconds=_FINDING_EXPLAIN_TTL_SECONDS,
    )

    with mock.patch.object(
        dashboard_mod,
        "explain_finding_verdict_to_human",
    ) as mock_explain:
        response = _post_finding_explain(client, scan_hash=scan_hash, finding_id=finding_id)

    assert response.status_code == status.HTTP_200_OK
    assert cached_prose in response.text
    mock_explain.assert_not_called()


def test_finding_explain_none_returns_unavailable_message(
    client: TestClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "db_path", tmp_path / "cache.db")
    scan = _cached_scan()

    with (
        mock.patch(
            "arguss.explanations.scan_cache.get_cached_scan_response",
            return_value=scan,
        ),
        mock.patch.object(
            dashboard_mod,
            "explain_finding_verdict_to_human",
            return_value=None,
        ),
    ):
        response = _post_finding_explain(client)

    assert response.status_code == status.HTTP_200_OK
    assert "No explanation available" in response.text
    assert "finding-explain-unavailable" in response.text


def test_finding_explain_unknown_finding_returns_muted_unavailable(
    client: TestClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_settings, "db_path", tmp_path / "cache.db")
    scan = _cached_scan(entries=[_scan_entry(finding_id="only-this-one")])

    with (
        mock.patch(
            "arguss.explanations.scan_cache.get_cached_scan_response",
            return_value=scan,
        ),
        mock.patch.object(
            dashboard_mod,
            "explain_finding_verdict_to_human",
        ) as mock_explain,
    ):
        response = _post_finding_explain(client, finding_id="does-not-exist")

    assert response.status_code == status.HTTP_200_OK
    assert "No explanation available" in response.text
    assert "finding-explain-unavailable" in response.text
    mock_explain.assert_not_called()
