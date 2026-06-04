"""Unit tests for remediation wizard helpers (phase 1)."""

from __future__ import annotations

import pytest

from arguss.core.models import FixTier
from arguss.web.wizard import (
    InvalidCandidateSelection,
    RescanSelectionChanged,
    classic_pat_create_url,
    filter_entries_for_action,
    fine_grained_pat_create_url,
    parse_repo_owner_name,
    repo_url_from_scan_meta,
    summarize_selected_candidates,
    validate_selection_against_cached,
    validate_selection_against_fresh_report,
)
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict
from tests.test_scan_with_action_endpoint import _proposal_entry


def test_fine_grained_pat_url_uses_documented_params() -> None:
    url = fine_grained_pat_create_url()
    assert url.startswith("https://github.com/settings/personal-access-tokens/new?")
    assert "name=Arguss" in url or "name=Arguss+" in url
    assert "description=Opens" in url
    assert "contents=write" in url
    assert "pull_requests=write" in url
    assert "expires_in=30" in url
    assert "expiration=" not in url
    assert "target_name=" not in url
    assert "workflows=" not in url


def test_fine_grained_pat_url_default_description() -> None:
    from urllib.parse import parse_qs, urlparse

    url = fine_grained_pat_create_url()
    params = parse_qs(urlparse(url).query)
    assert params["name"] == ["Arguss remediation"]
    assert params["expires_in"] == ["30"]
    assert params["contents"] == ["write"]
    assert params["pull_requests"] == ["write"]
    assert "Opens dependency remediation PRs" in params["description"][0]


def test_fine_grained_pat_url_includes_repo_in_description_when_given() -> None:
    url = fine_grained_pat_create_url(repo_display="ajrosales-max/test-as-package")
    assert "test-as-package" in url


def test_classic_pat_url() -> None:
    assert classic_pat_create_url() == "https://github.com/settings/tokens/new"


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


def test_validate_cached_rejects_non_auto_merge() -> None:
    scan = _cached_scan_dict(
        entries=[_cached_entry(package="risky", tier="review_required")],
    )
    cid = "cand-risky-001"
    with pytest.raises(InvalidCandidateSelection, match="not eligible"):
        validate_selection_against_cached(scan, [cid])


def test_validate_fresh_report_rescan_tier_change_message() -> None:
    auto = _proposal_entry(tier=FixTier.AUTO_MERGE, package="left-pad")
    review = _proposal_entry(tier=FixTier.REVIEW_REQUIRED, package="chalk")
    entries = (auto, review)
    with pytest.raises(RescanSelectionChanged) as exc_info:
        validate_selection_against_fresh_report(entries, [review.candidate.candidate_id])
    assert "re-scan changed" in str(exc_info.value).lower()
    assert "chalk" in str(exc_info.value)


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
