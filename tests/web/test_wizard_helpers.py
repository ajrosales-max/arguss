"""Unit tests for remediation wizard helpers (phase 1)."""

from __future__ import annotations

import pytest

from arguss.core.models import FixTier
from arguss.web.wizard import (
    InvalidCandidateSelection,
    filter_entries_for_action,
    parse_repo_owner_name,
    repo_url_from_scan_meta,
    summarize_selected_candidates,
    validate_selection_against_cached,
    validate_selection_against_fresh_report,
)
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict
from tests.test_scan_with_action_endpoint import _proposal_entry


def test_pat_url_helpers_removed() -> None:
    """The /action-era PAT URL helpers are gone and no template references them."""
    import arguss.web.wizard as wizard_mod

    assert not hasattr(wizard_mod, "fine_grained_pat_create_url")
    assert not hasattr(wizard_mod, "classic_pat_create_url")

    from pathlib import Path

    templates = Path("arguss/web/templates")
    for template in templates.rglob("*.html"):
        text = template.read_text()
        assert "fine_grained_pat_url" not in text, template
        assert "classic_pat_url" not in text, template


def test_parse_repo_owner_name() -> None:
    owner, name = parse_repo_owner_name({"repo_display": "ajrosales-max/test-as-package"})
    assert owner == "ajrosales-max"
    assert name == "test-as-package"


def test_repo_url_from_scan_meta() -> None:
    url = repo_url_from_scan_meta({"repo_display": "expressjs/express"})
    assert url == "https://github.com/expressjs/express"


def test_validate_cached_rejects_empty() -> None:
    scan = _cached_scan_dict(entries=[_cached_entry(package="a", tier="auto_merge")])
    with pytest.raises(InvalidCandidateSelection, match="at least one"):
        validate_selection_against_cached(scan, [])


def test_validate_cached_rejects_unknown_id() -> None:
    scan = _cached_scan_dict(entries=[_cached_entry(package="a", tier="auto_merge")])
    with pytest.raises(InvalidCandidateSelection, match="Unknown candidate"):
        validate_selection_against_cached(scan, ["not-a-real-id"])


def test_validate_cached_accepts_review_required() -> None:
    scan = _cached_scan_dict(
        entries=[_cached_entry(package="risky", tier="review_required")],
    )
    validate_selection_against_cached(scan, ["cand-risky-001"])


def test_validate_cached_rejects_decline_when_flag_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("arguss.web.wizard.settings.allow_decline_override", False)
    scan = _cached_scan_dict(entries=[_cached_entry(package="bad", tier="decline")])
    with pytest.raises(InvalidCandidateSelection, match="DECLINE override disabled"):
        validate_selection_against_cached(scan, ["cand-bad-001"])


def test_validate_fresh_report_accepts_review_required() -> None:
    auto = _proposal_entry(tier=FixTier.AUTO_MERGE, package="left-pad")
    review = _proposal_entry(tier=FixTier.REVIEW_REQUIRED, package="chalk")
    validate_selection_against_fresh_report((auto, review), [review.candidate.candidate_id])


def test_validate_fresh_report_rejects_unknown_id() -> None:
    auto = _proposal_entry(tier=FixTier.AUTO_MERGE, package="left-pad")
    with pytest.raises(InvalidCandidateSelection, match="Unknown candidate"):
        validate_selection_against_fresh_report((auto,), ["ghost-id"])


def test_filter_entries_none_returns_all_auto_merge() -> None:
    auto = _proposal_entry(tier=FixTier.AUTO_MERGE, package="a")
    review = _proposal_entry(tier=FixTier.REVIEW_REQUIRED, package="b")
    filtered = filter_entries_for_action((auto, review), None)
    assert len(filtered) == 1
    assert filtered[0].candidate.package == "a"


def test_filter_entries_selected_subset() -> None:
    a = _proposal_entry(tier=FixTier.AUTO_MERGE, package="a")
    b = _proposal_entry(tier=FixTier.AUTO_MERGE, package="b")
    filtered = filter_entries_for_action((a, b), [a.candidate.candidate_id])
    assert len(filtered) == 1
    assert filtered[0].candidate.package == "a"


def test_filter_entries_returns_review_required_override() -> None:
    auto = _proposal_entry(tier=FixTier.AUTO_MERGE, package="a")
    review = _proposal_entry(tier=FixTier.REVIEW_REQUIRED, package="b")
    filtered = filter_entries_for_action((auto, review), [review.candidate.candidate_id])
    assert len(filtered) == 1
    assert filtered[0].candidate.package == "b"


def test_filter_entries_raises_not_assert_on_mismatch() -> None:
    a = _proposal_entry(tier=FixTier.AUTO_MERGE, package="a")
    with pytest.raises(InvalidCandidateSelection, match="Missing"):
        filter_entries_for_action((a,), ["ghost-id-that-was-never-validated"])


def test_summarize_selected_candidates() -> None:
    scan = _cached_scan_dict(
        entries=[
            _cached_entry(package="pkg-a", tier="auto_merge"),
            _cached_entry(package="pkg-b", tier="auto_merge"),
        ],
    )
    ids = ["cand-pkg-a-001", "cand-pkg-b-001"]
    rows = summarize_selected_candidates(scan, ids)
    assert len(rows) == 2
    assert rows[0].package == "pkg-a"
    assert rows[1].package == "pkg-b"


def test_validate_fresh_report_accepts_rescan_with_stable_ids() -> None:
    """Assessment selection IDs match action re-scan when repo_identity is stable."""
    auto = _proposal_entry(tier=FixTier.AUTO_MERGE, package="left-pad")
    validate_selection_against_fresh_report((auto,), [auto.candidate.candidate_id])
