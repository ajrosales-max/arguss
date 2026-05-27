"""Tests for executive summary generation."""

from __future__ import annotations

from unittest import mock

from arguss.explanations import executive_summary as exec_mod


def _scan_result(*, entries: list[dict] | None = None) -> dict:
    return {
        "repo_path": "/tmp/repo",
        "lockfile_path": "/tmp/repo/package-lock.json",
        "entries": entries or [],
        "skipped_findings": [],
        "summary": {
            "total_findings": len(entries or []),
            "total_candidates": len(entries or []),
            "auto_merge_count": 0,
            "review_required_count": 0,
            "decline_count": 0,
        },
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


def test_generates_summary_when_claude_returns_text() -> None:
    scan = _scan_result()
    with (
        mock.patch.object(exec_mod, "call_claude", return_value="Test summary.") as mock_call,
        mock.patch.object(exec_mod, "_get_cache") as mock_cache_factory,
    ):
        cache = mock.MagicMock()
        cache.get_cached_text.return_value = None
        mock_cache_factory.return_value = cache
        result = exec_mod.generate_executive_summary(scan)

    assert result == "Test summary."
    mock_call.assert_called_once()


def test_returns_none_when_claude_fails() -> None:
    scan = _scan_result()
    with (
        mock.patch.object(exec_mod, "call_claude", return_value=None),
        mock.patch.object(exec_mod, "_get_cache") as mock_cache_factory,
    ):
        cache = mock.MagicMock()
        cache.get_cached_text.return_value = None
        mock_cache_factory.return_value = cache
        result = exec_mod.generate_executive_summary(scan)

    assert result is None


def test_caches_summary_by_input() -> None:
    scan = _scan_result(entries=[_entry(package="lodash", score=40)])
    with (
        mock.patch.object(exec_mod, "call_claude", return_value="Cached summary.") as mock_call,
        mock.patch.object(exec_mod, "_get_cache") as mock_cache_factory,
    ):
        cache = mock.MagicMock()
        cache.get_cached_text.return_value = None
        mock_cache_factory.return_value = cache

        first = exec_mod.generate_executive_summary(scan)
        cache.get_cached_text.return_value = "Cached summary."
        second = exec_mod.generate_executive_summary(scan)

    assert first == "Cached summary."
    assert second == "Cached summary."
    mock_call.assert_called_once()
    cache.set_cached_text.assert_called_once()


def test_different_inputs_produce_different_cache_keys() -> None:
    a = exec_mod.cache_key(exec_mod.build_claude_input(_scan_result()))
    b = exec_mod.cache_key(
        exec_mod.build_claude_input(
            _scan_result(entries=[_entry(package="axios", score=10)]),
        ),
    )
    assert a != b


def test_headline_packages_sorted_by_worst_score() -> None:
    scan = _scan_result(
        entries=[
            _entry(package="good-pkg", score=90),
            _entry(package="bad-pkg", score=15),
            _entry(package="mid-pkg", score=50),
            _entry(package="worse-pkg", score=5),
            _entry(package="also-bad", score=20),
            _entry(package="sixth-pkg", score=30),
        ],
    )
    claude_input = exec_mod.build_claude_input(scan)
    packages = [p["package"] for p in claude_input["headline_packages"]]
    assert packages == ["worse-pkg", "bad-pkg", "also-bad", "sixth-pkg", "mid-pkg"]
    assert claude_input["headline_packages"][0]["worst_score"] == 5
