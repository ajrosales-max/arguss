"""Comprehensive tests for REVIEW_REQUIRED/DECLINE override selection behavior."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest import mock

import pytest
from fastapi.testclient import TestClient

import arguss.web.dashboard as dashboard_mod
import arguss.web.github_action as ga
from arguss.api import app as api_app
from arguss.core.models import (
    Dependency,
    Finding,
    FixCandidate,
    FixConfidence,
    FixKind,
    FixTier,
)
from arguss.engine.fix_confidence import ENGINE_VERSION
from arguss.web.wizard import (
    InvalidCandidateSelection,
    filter_entries_for_action,
    validate_selection_against_cached,
)
from tests.test_candidate_selection_ui import _cached_entry, _cached_scan_dict
from tests.test_scan_with_action_endpoint import _proposal_entry
from tests.web.conftest import open_wizard_select, post_wizard_select


@pytest.fixture
def client() -> TestClient:
    return TestClient(api_app)


def _candidate(*, package: str = "left-pad") -> FixCandidate:
    return FixCandidate(
        package=package,
        from_version="1.0.0",
        to_version="1.0.1",
        fix_kind=FixKind.PATCH,
        source_finding_ids=("GHSA-test",),
        repo_id="/tmp/override-tests",
    )


def _finding(*, package: str = "left-pad") -> Finding:
    return Finding(
        dependency=Dependency(name=package, version="1.0.0", direct=True),
        lens="cve",
        severity="high",
        score=80.0,
        title="Test advisory",
        description="test",
        advisory_id="GHSA-test",
        source_url="https://github.com/advisories/GHSA-test",
    )


def _verdict(
    candidate: FixCandidate,
    *,
    tier: FixTier,
    score: int = 72,
    reasons: tuple[str, ...] = ("default reason",),
    veto_signals: tuple[str, ...] = ("pipeline.test_reality",),
) -> FixConfidence:
    return FixConfidence(
        candidate_id=candidate.candidate_id,
        tier=tier,
        score=score,
        reasons=reasons,
        veto_signals=veto_signals,
        evaluated_at=datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC),
        engine_version=ENGINE_VERSION,
    )


def test_validate_selection_accepts_review_required() -> None:
    scan = _cached_scan_dict(entries=[_cached_entry(package="review", tier="review_required")])
    validate_selection_against_cached(scan, ["cand-review-001"])


def test_validate_selection_accepts_decline_when_flag_on(allow_decline_override) -> None:
    allow_decline_override(True)
    scan = _cached_scan_dict(entries=[_cached_entry(package="declined", tier="decline")])
    validate_selection_against_cached(scan, ["cand-declined-001"])


def test_validate_selection_rejects_decline_when_flag_off(allow_decline_override) -> None:
    allow_decline_override(False)
    scan = _cached_scan_dict(entries=[_cached_entry(package="declined", tier="decline")])
    with pytest.raises(InvalidCandidateSelection, match="DECLINE override disabled"):
        validate_selection_against_cached(scan, ["cand-declined-001"])


def test_validate_selection_rejects_unknown_id() -> None:
    scan = _cached_scan_dict(entries=[_cached_entry(package="safe", tier="auto_merge")])
    with pytest.raises(InvalidCandidateSelection, match="Unknown candidate"):
        validate_selection_against_cached(scan, ["cand-missing-001"])


def test_validate_selection_rejects_empty() -> None:
    scan = _cached_scan_dict(entries=[_cached_entry(package="safe", tier="auto_merge")])
    with pytest.raises(InvalidCandidateSelection, match="at least one"):
        validate_selection_against_cached(scan, [])


def test_filter_entries_returns_review_required_override() -> None:
    auto = _proposal_entry(tier=FixTier.AUTO_MERGE, package="safe")
    review = _proposal_entry(tier=FixTier.REVIEW_REQUIRED, package="review")
    filtered = filter_entries_for_action((auto, review), [review.candidate.candidate_id])
    assert len(filtered) == 1
    assert filtered[0].candidate.package == "review"


def test_filter_entries_returns_decline_when_selected_and_allowed(allow_decline_override) -> None:
    allow_decline_override(True)
    auto = _proposal_entry(tier=FixTier.AUTO_MERGE, package="safe")
    decline = _proposal_entry(tier=FixTier.DECLINE, package="declined")
    filtered = filter_entries_for_action((auto, decline), [decline.candidate.candidate_id])
    assert len(filtered) == 1
    assert filtered[0].candidate.package == "declined"


def test_filter_entries_none_selection_keeps_auto_merge_only() -> None:
    auto_a = _proposal_entry(tier=FixTier.AUTO_MERGE, package="a")
    auto_b = _proposal_entry(tier=FixTier.AUTO_MERGE, package="b")
    review = _proposal_entry(tier=FixTier.REVIEW_REQUIRED, package="review")
    filtered = filter_entries_for_action((auto_a, auto_b, review), None)
    assert [entry.candidate.package for entry in filtered] == ["a", "b"]


def test_select_ui_review_checkbox_enabled(client, wizard_db, allow_decline_override) -> None:
    allow_decline_override(True)
    scan = _cached_scan_dict(entries=[_cached_entry(package="review", tier="review_required")])
    response = open_wizard_select(client, "review-enabled", scan, wizard_db=wizard_db)

    idx = response.text.index('value="cand-review-001"')
    snippet = response.text[idx : idx + 200]
    assert "disabled" not in snippet


def test_select_ui_decline_checkbox_enabled_when_flag_on(
    client, wizard_db, allow_decline_override
) -> None:
    allow_decline_override(True)
    scan = _cached_scan_dict(entries=[_cached_entry(package="declined", tier="decline")])
    response = open_wizard_select(client, "decline-enabled", scan, wizard_db=wizard_db)

    idx = response.text.index('value="cand-declined-001"')
    snippet = response.text[idx : idx + 220]
    assert "disabled" not in snippet


def test_select_ui_decline_checkbox_disabled_when_flag_off(
    client, wizard_db, allow_decline_override
) -> None:
    allow_decline_override(False)
    scan = _cached_scan_dict(entries=[_cached_entry(package="declined", tier="decline")])
    response = open_wizard_select(client, "decline-disabled", scan, wizard_db=wizard_db)

    idx = response.text.index('value="cand-declined-001"')
    snippet = response.text[idx : idx + 220]
    assert "disabled" in snippet


def test_select_ui_shows_override_warning_indicators(
    client, wizard_db, allow_decline_override
) -> None:
    allow_decline_override(True)
    scan = _cached_scan_dict(
        entries=[
            _cached_entry(package="review", tier="review_required"),
            _cached_entry(package="declined", tier="decline"),
        ]
    )
    response = open_wizard_select(client, "override-indicators", scan, wizard_db=wizard_db)

    text = response.text
    assert "override-warning-review" in text
    assert "override-warning-decline" in text
    assert "candidate-row-decline" in text


def test_select_ui_decline_modal_markup_present(client, wizard_db, allow_decline_override) -> None:
    allow_decline_override(True)
    scan = _cached_scan_dict(entries=[_cached_entry(package="declined", tier="decline")])
    response = open_wizard_select(client, "decline-modal", scan, wizard_db=wizard_db)

    text = response.text
    assert 'id="decline-override-modal"' in text
    assert "Confirm decline override" in text
    assert "decline-override-modal-list" in text


def test_post_select_accepts_review_required(client, wizard_db, allow_decline_override) -> None:
    allow_decline_override(True)
    scan = _cached_scan_dict(entries=[_cached_entry(package="review", tier="review_required")])
    open_wizard_select(client, "post-review", scan, wizard_db=wizard_db)

    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = post_wizard_select(client, ["cand-review-001"])
    assert response.status_code == 200
    assert "Authorize GitHub access" in response.text


def test_post_select_rejects_decline_when_flag_off(
    client, wizard_db, allow_decline_override
) -> None:
    allow_decline_override(False)
    scan = _cached_scan_dict(entries=[_cached_entry(package="declined", tier="decline")])
    open_wizard_select(client, "post-decline-off", scan, wizard_db=wizard_db)

    with mock.patch.object(dashboard_mod, "get_cached_scan_response", return_value=scan):
        response = post_wizard_select(client, ["cand-declined-001"])
    assert response.status_code == 400
    assert "DECLINE override disabled" in response.text


def test_render_pr_body_has_no_override_warning_for_auto_merge() -> None:
    candidate = _candidate()
    finding = _finding()
    verdict = _verdict(
        candidate, tier=FixTier.AUTO_MERGE, reasons=("safe to auto-merge",), veto_signals=()
    )

    body = ga._render_pr_body(candidate, verdict, finding)
    assert "User-overridden auto-merge envelope" not in body


def test_render_pr_body_includes_override_warning_for_review_required() -> None:
    candidate = _candidate(package="review")
    finding = _finding(package="review")
    verdict = _verdict(
        candidate,
        tier=FixTier.REVIEW_REQUIRED,
        score=67,
        reasons=("Tests do not fully cover this upgrade",),
        veto_signals=("pipeline.test_reality",),
    )

    body = ga._render_pr_body(candidate, verdict, finding)
    assert "User-overridden auto-merge envelope" in body
    assert "REVIEW_REQUIRED" in body
    assert "score 67/100" in body


def test_render_pr_body_includes_decline_override_warning() -> None:
    candidate = _candidate(package="declined")
    finding = _finding(package="declined")
    verdict = _verdict(
        candidate,
        tier=FixTier.DECLINE,
        score=22,
        reasons=("Breaking-major risk too high",),
        veto_signals=("trust.breaking_change",),
    )

    body = ga._render_pr_body(candidate, verdict, finding)
    assert "Arguss **DECLINED** this candidate" in body
    assert "score: 22/100" in body
    assert "Breaking-major risk too high" in body


def test_render_pr_body_override_reasons_are_verbatim_with_signals() -> None:
    candidate = _candidate(package="verbatim")
    finding = _finding(package="verbatim")
    reason_a = "Pipeline has no required CI checks on default branch"
    reason_b = "Upgrade crosses major versions with possible runtime breakage"
    verdict = _verdict(
        candidate,
        tier=FixTier.REVIEW_REQUIRED,
        score=41,
        reasons=(reason_a, reason_b),
        veto_signals=("pipeline.test_reality", "trust.breaking_change"),
    )

    body = ga._render_pr_body(candidate, verdict, finding)
    assert f"`pipeline.test_reality` - {reason_a}" in body
    assert f"`trust.breaking_change` - {reason_b}" in body
    assert "score 41/100" in body
