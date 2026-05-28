"""Tests for dashboard chat panel and scan-grounded Q&A."""

from __future__ import annotations

import json
from unittest import mock

import pytest
from fastapi import status
from fastapi.testclient import TestClient

import arguss.api as api_mod
import arguss.settings as settings_mod
import arguss.web.auth as auth_mod
from arguss.api import create_app
from arguss.explanations import executive_summary as exec_mod
from arguss.explanations import scan_cache as scan_cache_mod
from arguss.explanations.chat import ChatMessage, _compact_scan_data
from arguss.explanations.scan_cache import (
    cache_scan_response,
    scan_input_hash,
)
from arguss.settings import Settings


def _scan_payload(*, entries: list[dict] | None = None) -> dict:
    entries = entries or []
    return {
        "repo_path": "/tmp/repo",
        "lockfile_path": "/tmp/repo/package-lock.json",
        "entries": entries,
        "skipped_findings": [],
        "summary": {
            "total_findings": len(entries),
            "total_candidates": len(entries),
            "auto_merge_count": 0,
            "review_required_count": 0,
            "decline_count": 0,
        },
        "project_scores": {},
        "executive_summary": None,
    }


def _entry(*, package: str, score: int, tier: str = "review_required") -> dict:
    return {
        "finding": {"severity": "high"},
        "candidate": {"package": package},
        "verdict": {
            "score": score,
            "tier": tier,
            "veto_signals": [],
            "reasons": ["reason-a"],
        },
    }


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def _post_chat(
    client: TestClient,
    *,
    scan_hash: str = "deadbeef",
    question: str = "What should I review first?",
    history_json: str = "[]",
):
    return client.post(
        "/dashboard/chat",
        data={
            "scan_input_hash": scan_hash,
            "history_json": history_json,
            "question": question,
        },
    )


def test_chat_returns_assistant_message_on_success(client: TestClient) -> None:
    scan = _scan_payload(entries=[_entry(package="lodash", score=40)])
    with (
        mock.patch(
            "arguss.explanations.chat.get_cached_scan_response",
            return_value=scan,
        ),
        mock.patch(
            "arguss.explanations.chat.call_claude",
            return_value="Test answer.",
        ),
    ):
        response = _post_chat(client, scan_hash="abc123")

    assert response.status_code == status.HTTP_200_OK
    assert "Test answer." in response.text


def test_chat_returns_error_when_scan_hash_unknown(client: TestClient) -> None:
    with mock.patch(
        "arguss.explanations.chat.get_cached_scan_response",
        return_value=None,
    ):
        response = _post_chat(client)

    assert response.status_code == status.HTTP_200_OK
    assert "Chat is currently unavailable" in response.text


def test_chat_returns_error_when_claude_fails(client: TestClient) -> None:
    scan = _scan_payload()
    with (
        mock.patch(
            "arguss.explanations.chat.get_cached_scan_response",
            return_value=scan,
        ),
        mock.patch("arguss.explanations.chat.call_claude", return_value=None),
    ):
        response = _post_chat(client)

    assert response.status_code == status.HTTP_200_OK
    assert "Chat is currently unavailable" in response.text


def test_chat_compacts_scan_data() -> None:
    entries = [_entry(package=f"pkg-{i}", score=100 - i) for i in range(200)]
    compact = _compact_scan_data(_scan_payload(entries=entries))
    assert len(compact["headline_entries"]) <= 10


def test_chat_compacts_picks_worst_score_per_package() -> None:
    scan = _scan_payload(
        entries=[
            _entry(package="lodash", score=80),
            _entry(package="lodash", score=20),
        ],
    )
    compact = _compact_scan_data(scan)
    lodash_entries = [e for e in compact["headline_entries"] if e.get("package") == "lodash"]
    assert len(lodash_entries) == 1
    assert lodash_entries[0]["verdict"]["score"] == 20


def test_chat_history_truncated_at_20_turns(client: TestClient) -> None:
    scan = _scan_payload()
    history = [ChatMessage(role="user", content=f"q{i}") for i in range(50)]
    with (
        mock.patch(
            "arguss.explanations.chat.get_cached_scan_response",
            return_value=scan,
        ),
        mock.patch(
            "arguss.explanations.chat.call_claude",
            return_value="ok",
        ) as mock_claude,
    ):
        _post_chat(
            client,
            question="follow-up",
            history_json=json.dumps([m.model_dump() for m in history]),
        )

    user_message = mock_claude.call_args.kwargs["user_message"]
    assert "q30" in user_message
    assert "q0" not in user_message


def test_chat_history_persists_across_turns(client: TestClient) -> None:
    scan = _scan_payload()
    with (
        mock.patch(
            "arguss.explanations.chat.get_cached_scan_response",
            return_value=scan,
        ),
        mock.patch(
            "arguss.explanations.chat.call_claude",
            side_effect=["First answer.", "Second answer."],
        ) as mock_claude,
    ):
        first = _post_chat(client, question="First question?")
        assert first.status_code == status.HTTP_200_OK
        assert "First answer." in first.text
        new_history_json = json.dumps(
            [
                {"role": "user", "content": "First question?"},
                {"role": "assistant", "content": "First answer."},
            ],
        )
        second = _post_chat(
            client,
            question="Second question?",
            history_json=new_history_json,
        )

    assert second.status_code == status.HTTP_200_OK
    user_message = mock_claude.call_args.kwargs["user_message"]
    assert "First question?" in user_message
    assert "First answer." in user_message
    assert "Second question?" in user_message


def test_chat_endpoint_requires_demo_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Settings, "demo_password", "secret")
    patched = Settings()
    monkeypatch.setattr(settings_mod, "settings", patched)
    monkeypatch.setattr(auth_mod, "settings", patched)
    monkeypatch.setattr(api_mod, "settings", patched)

    client = TestClient(create_app())
    response = _post_chat(client)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_scan_input_hash_matches_executive_summary_key() -> None:
    scan = _scan_payload(entries=[_entry(package="axios", score=10)])
    claude_input = exec_mod.build_claude_input(scan)
    assert scan_input_hash(scan) == exec_mod.cache_key(claude_input)


def test_cache_scan_response_stores_payload() -> None:
    scan = _scan_payload(entries=[_entry(package="lodash", score=40)])
    with mock.patch.object(scan_cache_mod, "_get_cache") as mock_cache_factory:
        cache = mock.MagicMock()
        mock_cache_factory.return_value = cache
        key = cache_scan_response(scan)

    expected_key = scan_input_hash(scan)
    assert key == expected_key
    cache.set_api_response.assert_called_once()
    call_args = cache.set_api_response.call_args
    assert call_args[0][0] == "scan_response"
    assert call_args[0][1] == expected_key
    assert call_args[0][2] == scan
