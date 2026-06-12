"""Canonical score formula strings derived from engine constants.

Single source for UI breakdown tooltips and chat system-prompt mechanics.
Strings are formatted from the same constants the lenses and fix-confidence
engine use so drift is structurally impossible.
"""

from __future__ import annotations

from arguss.core.models import ZizmorSeverity
from arguss.engine import fix_confidence as fix_confidence_mod
from arguss.lenses.pipeline import (
    _PIPELINE_SUBSCORE_WEIGHTS,
    _SUBSCORE_CAP,
    _TEST_REALITY_PENALTY,
)
from arguss.lenses.trust import _TRUST_LENS_TOP_N, TRUST_SUBSCORE_WEIGHTS
from arguss.lenses.vulnerability import _normalize_cvss_to_100
from arguss.scoring.unified import DEFAULT_WEIGHTS

# Missing CVSS default is 50.0 in arguss/lenses/vulnerability.py (_normalize_cvss_to_100).
_MISSING_CVSS_NORMALIZED = int(_normalize_cvss_to_100(None))

_FIX_CONFIDENCE_START = 100
_FIX_CONFIDENCE_FLOOR = 1

_ZIZMOR_SEVERITY_ORDER: tuple[ZizmorSeverity, ...] = (
    "informational",
    "low",
    "medium",
    "high",
)

_VETO_DELTA_LABELS: dict[str, str] = {
    "fix_kind.major": "major version bump",
    "trust.unavailable": "trust unavailable",
    "trust.ownership_transferred": "ownership transfer",
    "trust.new_maintainer": "new maintainer",
    "trust.cadence_anomaly": "cadence anomaly",
    "trust.download_collapse": "download collapse",
    "pipeline.unavailable": "pipeline unavailable",
    "pipeline.test_reality": "test_reality",
}

WORKFLOW_NOT_APPLICABLE_FORMULA = "not_applicable when no workflows are present to analyze"

TEST_REALITY_BREAKDOWN_FORMULA = (
    "verified when all four conditions pass; otherwise vetoed for auto-merge"
)


def format_prs_formula() -> str:
    w = DEFAULT_WEIGHTS
    return (
        f"PRS = round({w['cve']:.0%}×CVE + {w['trust']:.0%}×Trust + {w['pipeline']:.0%}×Pipeline)"
    )


def format_vulnerability_formula() -> str:
    return (
        "subscore = max over findings of min(100, CVSS × 10); "
        f"missing CVSS → {_MISSING_CVSS_NORMALIZED}"
    )


def format_trust_formula(*, top_n: int = _TRUST_LENS_TOP_N) -> str:
    w = TRUST_SUBSCORE_WEIGHTS
    return (
        f"Per-package snapshot risk (0–100): sole maintainer +{w.sole_maintainer}, "
        f"young package +{w.young_package}, typosquat +{w.typosquat_distance_1}/"
        f"+{w.typosquat_distance_2}, low downloads +{w.low_weekly_downloads}; "
        f"project subscore = mean(top {top_n} highest)"
    )


def format_zizmor_reference_formula() -> str:
    """All severities — canonical reference for chat and docs."""
    parts = [
        f"{severity}×{_PIPELINE_SUBSCORE_WEIGHTS[severity]}" for severity in _ZIZMOR_SEVERITY_ORDER
    ]
    inner = " + ".join(parts)
    return f"min({_SUBSCORE_CAP}, ({inner}))"


def format_zizmor_breakdown_formula(z_counts: dict[str, int]) -> str:
    """Per-scan zizmor-only formula (matches workflow security breakdown tile)."""
    parts = [
        f"{severity}×{_PIPELINE_SUBSCORE_WEIGHTS[severity]}"
        for severity in _ZIZMOR_SEVERITY_ORDER
        if z_counts.get(severity)
    ]
    z_part = " + ".join(parts) if parts else "0"
    return f"min({_SUBSCORE_CAP}, ({z_part}))"


def format_pipeline_prs_input_formula() -> str:
    return (
        f"pipeline subscore for PRS = min({_SUBSCORE_CAP}, zizmor weighted sum + "
        f"{_TEST_REALITY_PENALTY} when test-reality fails)"
    )


def format_fix_confidence_formula() -> str:
    reductions = fix_confidence_mod._SCORE_REDUCTION
    examples = ", ".join(
        f"{_VETO_DELTA_LABELS.get(signal, signal)} −{delta}"
        for signal, delta in sorted(reductions.items(), key=lambda item: (-item[1], item[0]))
    )
    return (
        f"starts at {_FIX_CONFIDENCE_START}, veto deltas subtract "
        f"({examples}), floored at {_FIX_CONFIDENCE_FLOOR}"
    )


def build_chat_score_mechanics_section() -> str:
    """Score mechanics block for the chat system prompt (no str.format placeholders)."""
    return (
        "Score mechanics — the ONLY permitted explanations:\n"
        "Explain lens and fix-confidence scores ONLY using these formulas. "
        "Do not describe deductions from 100, averaging, or any mechanic not listed. "
        "If the scan context lacks the data needed to answer, say so. "
        "Never invent counts, mechanics, or attributions.\n"
        f"   - PRS: {format_prs_formula()}\n"
        f"   - Vulnerability subscore: {format_vulnerability_formula()}\n"
        f"   - Trust subscore: {format_trust_formula()}\n"
        f"   - Workflow/zizmor subscore (tile): {format_zizmor_reference_formula()}\n"
        f"   - Pipeline input to PRS: {format_pipeline_prs_input_formula()}\n"
        f"   - Fix-confidence score: {format_fix_confidence_formula()}\n"
    )
