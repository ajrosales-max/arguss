"""Unit tests for results page context and score breakdown builders."""

from __future__ import annotations

from typing import Any

from arguss.web.results_context import (
    _prs_tier,
    build_results_context,
    build_test_reality_breakdown,
    build_workflow_security_breakdown,
)


def test_workflow_security_breakdown_not_applicable_when_no_workflows() -> None:
    """When no workflows exist, the breakdown reports not_applicable rather than zero."""
    cached: dict[str, Any] = {
        "project_scores": {"pipeline_subscore": 40},
        "lens_explain": {
            "pipeline": {
                "workflow_files": [],
                "zizmor_weighted_sum": 0,
                "test_penalty": 40,
                "subscore": 40,
            }
        },
    }
    bd = build_workflow_security_breakdown(cached)
    assert bd.final_value == "not_applicable"
    assert "no github actions workflows were found" in bd.description.lower()
    line_labels = [label for label, _ in bd.lines]
    assert "Workflows present" in line_labels
    assert not any("test-reality penalty" in label.lower() for label in line_labels)


def test_workflow_security_breakdown_numeric_when_workflows_exist() -> None:
    """When workflows exist, the breakdown reports the numeric zizmor-only score."""
    cached: dict[str, Any] = {
        "project_scores": {"pipeline_subscore": 100},
        "lens_explain": {
            "pipeline": {
                "workflow_files": [".github/workflows/ci.yml"],
                "zizmor_weighted_sum": 285,
                "test_penalty": 0,
                "subscore": 100,
                "zizmor_counts": {"medium": 3, "high": 8},
            }
        },
    }
    bd = build_workflow_security_breakdown(cached)
    assert bd.final_value == 100


def test_workflow_security_breakdown_with_real_zizmor_findings() -> None:
    """Mode A axios pattern: zizmor finds real issues, test-reality passes."""
    cached: dict[str, Any] = {
        "project_scores": {"pipeline_subscore": 100},
        "lens_explain": {
            "pipeline": {
                "zizmor_weighted_sum": 285,
                "test_penalty": 0,
                "subscore": 100,
                "workflow_files": [".github/workflows/ci.yml"],
                "zizmor_counts": {"medium": 3, "high": 8},
            }
        },
    }
    bd = build_workflow_security_breakdown(cached)
    assert bd.final_value == 100


def test_results_context_workflow_security_not_applicable_with_no_workflows() -> None:
    """The context exposes workflow_security_subscore as 'not_applicable' when no workflows."""
    cached: dict[str, Any] = {
        "entries": [],
        "project_scores": {
            "vulnerability_subscore": 50,
            "trust_subscore": 20,
            "pipeline_subscore": 40,
        },
        "lens_explain": {
            "pipeline": {
                "workflow_files": [],
                "zizmor_weighted_sum": 0,
                "test_penalty": 40,
                "subscore": 40,
            }
        },
        "summary": {
            "total_findings": 0,
            "auto_merge_count": 0,
            "review_required_count": 0,
            "decline_count": 0,
        },
        "skipped_findings": [],
    }
    context = build_results_context(cached, "test-hash-12345")
    assert context["scan"]["workflow_security_subscore"] == "not_applicable"


def test_results_context_workflow_security_numeric_with_workflows() -> None:
    """The context exposes a numeric value when workflows exist."""
    cached: dict[str, Any] = {
        "entries": [],
        "project_scores": {"pipeline_subscore": 100},
        "lens_explain": {
            "pipeline": {
                "workflow_files": [".github/workflows/ci.yml"],
                "zizmor_weighted_sum": 285,
                "test_penalty": 0,
                "subscore": 100,
            }
        },
        "summary": {
            "total_findings": 0,
            "auto_merge_count": 0,
            "review_required_count": 0,
            "decline_count": 0,
        },
        "skipped_findings": [],
    }
    context = build_results_context(cached, "test-hash-12345")
    assert context["scan"]["workflow_security_subscore"] == 100


def test_prs_tier_directions() -> None:
    """PRS tier: high = danger (lots of risk), low = safe (clean)."""
    assert _prs_tier(85) == "danger"
    assert _prs_tier(50) == "caution"
    assert _prs_tier(15) == "safe"
    assert _prs_tier(None) == "caution"


def test_chat_suggested_questions_in_context() -> None:
    """The results context exposes the four hardcoded chat starter questions."""
    cached: dict[str, Any] = {
        "entries": [],
        "project_scores": {},
        "summary": {
            "total_findings": 0,
            "auto_merge_count": 0,
            "review_required_count": 0,
            "decline_count": 0,
        },
        "skipped_findings": [],
        "lens_explain": {},
    }
    context = build_results_context(cached, "test-hash")
    assert "chat_suggested_questions" in context
    assert len(context["chat_suggested_questions"]) == 4
    assert any("worst-scoring" in q for q in context["chat_suggested_questions"])
    assert any("Slack message" in q for q in context["chat_suggested_questions"])


def test_chat_endpoint_url_in_context() -> None:
    """The chat endpoint URL is computed from the scan hash."""
    cached: dict[str, Any] = {
        "entries": [],
        "project_scores": {},
        "summary": {
            "total_findings": 0,
            "auto_merge_count": 0,
            "review_required_count": 0,
            "decline_count": 0,
        },
        "skipped_findings": [],
        "lens_explain": {},
    }
    context = build_results_context(cached, "abc123")
    assert "chat_endpoint_url" in context
    assert "abc123" in context["chat_endpoint_url"]


def test_test_reality_breakdown_mentions_penalty_in_description() -> None:
    """Test Verification breakdown describes penalty affecting PRS pipeline subscore."""
    cached: dict[str, Any] = {
        "project_scores": {"test_reality": "vetoed"},
        "lens_explain": {
            "pipeline": {
                "workflow_files": [".github/workflows/ci.yml"],
                "test_reality": {
                    "has_test_script": False,
                    "test_script_is_no_op": False,
                    "has_test_files": False,
                    "test_count": 0,
                    "workflow_runs_tests": False,
                    "safe_to_auto_merge": False,
                    "reasons_blocked": [],
                },
            }
        },
    }
    bd = build_test_reality_breakdown(cached)
    assert "pipeline" in bd.description.lower() or "prs" in bd.description.lower()


def test_finding_card_score_tier_direction() -> None:
    from arguss.web.results_context import finding_confidence_score_tier

    assert finding_confidence_score_tier(70) == "safe"
    assert finding_confidence_score_tier(85) == "safe"
    assert finding_confidence_score_tier(30) == "caution"
    assert finding_confidence_score_tier(69) == "caution"
    assert finding_confidence_score_tier(29) == "danger"
    assert finding_confidence_score_tier(0) == "danger"


def test_mode_b_pipeline_test_reality_reason_suggests_mode_a() -> None:
    from arguss.web.results_context import apply_mode_aware_verdict_reasons

    cached = {
        "scan_meta": {"mode": "B"},
        "entries": [
            {
                "verdict": {
                    "veto_signals": ["pipeline.test_reality"],
                    "reasons": [
                        "pipeline veto: Your project's CI provides no test signal. "
                        "The agent cannot verify behavior post-upgrade."
                    ],
                }
            }
        ],
    }
    out = apply_mode_aware_verdict_reasons(cached)
    reasons = out["entries"][0]["verdict"]["reasons"]
    assert any("mode a" in r.lower() for r in reasons)


def _sample_entry(
    *,
    tier: str,
    package: str = "minimatch",
    veto_signals: tuple[str, ...] = (),
    reasons: tuple[str, ...] = ("default reason",),
) -> dict:
    cid = f"cand-{package}"
    return {
        "candidate": {
            "package": package,
            "from_version": "9.0.5",
            "to_version": "9.0.7",
            "candidate_id": cid,
        },
        "verdict": {
            "tier": tier,
            "score": 55,
            "veto_signals": veto_signals,
            "reasons": list(reasons),
            "candidate_id": cid,
        },
        "finding": {
            "severity": "high",
            "dependency": {"name": package, "version": "9.0.5"},
        },
    }


def test_candidates_grouped_by_tier() -> None:
    from arguss.web.results_context import build_candidates_by_tier

    cached = {
        "entries": [
            _sample_entry(tier="auto_merge", package="a"),
            _sample_entry(tier="review_required", package="b"),
            _sample_entry(tier="decline", package="c"),
        ]
    }
    grouped = build_candidates_by_tier(cached)
    assert grouped["total_count"] == 3
    assert len(grouped["auto_merge"]) == 1
    assert len(grouped["review_required"]) == 1
    assert len(grouped["decline"]) == 1
    assert grouped["auto_merge"][0].package == "a"
    assert grouped["review_required"][0].package == "b"
    assert grouped["decline"][0].package == "c"


def test_auto_merge_section_present_when_auto_merge_candidates_exist() -> None:
    from arguss.web.results_context import build_results_context

    cached = {
        "entries": [_sample_entry(tier="auto_merge")],
        "project_scores": {},
        "summary": {
            "total_findings": 1,
            "auto_merge_count": 1,
            "review_required_count": 0,
            "decline_count": 0,
        },
        "skipped_findings": [],
        "scan_meta": {"mode": "A"},
    }
    context = build_results_context(cached, "hash-auto")
    assert context["show_candidate_selection"] is True
    assert len(context["candidates_by_tier"]["auto_merge"]) == 1


def test_review_required_candidates_carry_veto_reasons() -> None:
    from arguss.web.results_context import build_candidates_by_tier

    cached = {
        "entries": [
            _sample_entry(
                tier="review_required",
                veto_signals=("pipeline.test_reality",),
                reasons=("CI cannot verify tests",),
            )
        ]
    }
    candidate = build_candidates_by_tier(cached)["review_required"][0]
    assert candidate.veto_signals == ("pipeline.test_reality",)
    assert candidate.reasons == ("CI cannot verify tests",)
    assert candidate.checked_by_default is False


def test_decline_candidates_carry_veto_reasons() -> None:
    from arguss.web.results_context import build_candidates_by_tier

    cached = {
        "entries": [
            _sample_entry(
                tier="decline",
                package="risky",
                veto_signals=("trust.ownership_transferred", "fix_kind.major"),
                reasons=("No safe upgrade path",),
            )
        ]
    }
    candidate = build_candidates_by_tier(cached)["decline"][0]
    assert "trust.ownership_transferred" in candidate.veto_signals
    assert candidate.reasons == ("No safe upgrade path",)
    assert candidate.checked_by_default is False
